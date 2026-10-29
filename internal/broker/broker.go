// Package broker is an mTLS secret broker for AI agents.
//
// Agents never receive long-lived API keys. Instead they:
//
//  1. authenticate with an mTLS client certificate (SPIFFE-style identity),
//  2. request a short-lived token scoped to one upstream (or one secret),
//  3. call the upstream *through* the broker, which checks the token,
//     the method/path allowlist and the request budget, injects the real
//     credential, and redacts it from the response if the upstream echoes it.
//
// Even a fully prompt-injected agent can therefore only make the specific
// calls its policy allows, for a few minutes, and can never exfiltrate the key.
package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/koheip/kagi/internal/audit"
	"github.com/koheip/kagi/internal/pki"
	"github.com/koheip/kagi/internal/policy"
	"github.com/koheip/kagi/internal/ratelimit"
	"github.com/koheip/kagi/internal/token"
	"github.com/koheip/kagi/internal/vault"
)

type Config struct {
	Policy *policy.Policy
	Vault  *vault.Vault
	Audit  *audit.Log
	Logger *slog.Logger

	// UpstreamRootCAs overrides the system roots for upstream TLS (tests).
	UpstreamRootCAs *x509.CertPool
	// AllowPrivateUpstreams disables the SSRF egress guard (dev only).
	AllowPrivateUpstreams bool

	TokenRate, ProxyRate   float64 // per agent, events/second
	TokenBurst, ProxyBurst int
	MaxBodyBytes           int64
}

type usage struct {
	used int
	exp  int64
}

type Broker struct {
	cfg       Config
	log       *slog.Logger
	policy    atomic.Pointer[policy.Policy]
	issuer    *token.Issuer
	tokLim    *ratelimit.Limiter
	proxyLim  *ratelimit.Limiter
	transport *http.Transport
	metrics   *metrics
	now       func() time.Time

	mu      sync.Mutex
	usage   map[string]*usage // jti -> budget consumption
	revoked map[string]int64  // jti -> exp (kept until expiry)
}

func New(cfg Config) (*Broker, error) {
	if cfg.Policy == nil || cfg.Vault == nil || cfg.Audit == nil {
		return nil, errors.New("broker: policy, vault and audit are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TokenRate == 0 {
		cfg.TokenRate, cfg.TokenBurst = 1, 10
	}
	if cfg.ProxyRate == 0 {
		cfg.ProxyRate, cfg.ProxyBurst = 10, 50
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 10 << 20
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: egressControl(cfg.AllowPrivateUpstreams)}
	b := &Broker{
		cfg:      cfg,
		log:      cfg.Logger,
		issuer:   token.NewIssuer(),
		tokLim:   ratelimit.New(cfg.TokenRate, cfg.TokenBurst),
		proxyLim: ratelimit.New(cfg.ProxyRate, cfg.ProxyBurst),
		metrics:  newMetrics(),
		now:      time.Now,
		usage:    map[string]*usage{},
		revoked:  map[string]int64{},
		transport: &http.Transport{
			Proxy:                 nil, // never route secrets via env-configured proxies
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.UpstreamRootCAs},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 120 * time.Second,
		},
	}
	b.policy.Store(cfg.Policy)
	return b, nil
}

// SetPolicy atomically swaps the policy (e.g. on SIGHUP). Tokens whose
// grant disappears stop working immediately.
func (b *Broker) SetPolicy(p *policy.Policy) { b.policy.Store(p) }

// ServerTLSConfig requires TLS 1.3 and verified client certificates and
// prefers the hybrid post-quantum key exchange X25519MLKEM768
// (protects recorded traffic against "harvest now, decrypt later").
func ServerTLSConfig(cert tls.Certificate, clientCAs *x509.CertPool, pqOnly bool) *tls.Config {
	curves := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	if pqOnly {
		curves = []tls.CurveID{tls.X25519MLKEM768}
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		CurvePreferences: curves,
		NextProtos:       []string{"h2", "http/1.1"},
	}
}

// RunJanitor periodically forgets expired budgets and revocations.
func (b *Broker) RunJanitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := b.now().Unix()
			b.mu.Lock()
			for k, u := range b.usage {
				if u.exp <= now {
					delete(b.usage, k)
				}
			}
			for k, exp := range b.revoked {
				if exp <= now {
					delete(b.revoked, k)
				}
			}
			b.mu.Unlock()
		}
	}
}

// --- HTTP surface --------------------------------------------------------

type ctxKey struct{}

type principal struct {
	id    pki.Identity
	thumb string
}

func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token", b.agentOnly(b.handleToken))
	mux.HandleFunc("/v1/proxy/{upstream}/{rest...}", b.agentOnly(b.handleProxy))
	mux.HandleFunc("GET /v1/secrets/{name...}", b.agentOnly(b.handleReveal))
	mux.HandleFunc("GET /v1/admin/secrets", b.adminOnly(b.handleAdminList))
	mux.HandleFunc("PUT /v1/admin/secrets/{name...}", b.adminOnly(b.handleAdminPut))
	mux.HandleFunc("DELETE /v1/admin/secrets/{name...}", b.adminOnly(b.handleAdminDelete))
	mux.HandleFunc("POST /v1/admin/revoke", b.adminOnly(b.handleAdminRevoke))
	return b.authenticate(mux)
}

func (b *Broker) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			b.metrics.inc("auth_failures_total")
			writeErr(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		id, err := pki.IdentityFromCert(leaf)
		if err != nil {
			b.metrics.inc("auth_failures_total")
			writeErr(w, http.StatusUnauthorized, "unrecognized client identity")
			return
		}
		p := &principal{id: id, thumb: pki.Thumbprint(leaf)}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func (b *Broker) requireKind(k pki.Kind, h func(http.ResponseWriter, *http.Request, *principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.Context().Value(ctxKey{}).(*principal)
		if p.id.Kind != k {
			b.deny(p, r.Method+" "+r.URL.Path, "wrong role")
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		h(w, r, p)
	}
}

func (b *Broker) agentOnly(h func(http.ResponseWriter, *http.Request, *principal)) http.HandlerFunc {
	return b.requireKind(pki.KindAgent, h)
}

func (b *Broker) adminOnly(h func(http.ResponseWriter, *http.Request, *principal)) http.HandlerFunc {
	return b.requireKind(pki.KindAdmin, h)
}

// --- agent: token issuance ----------------------------------------------

type tokenRequest struct {
	Upstream string `json:"upstream,omitempty"`
	Secret   string `json:"secret,omitempty"`
	TTL      string `json:"ttl,omitempty"`
	Purpose  string `json:"purpose,omitempty"` // free text, recorded in audit log
}

type tokenResponse struct {
	Token       string    `json:"token"`
	TokenID     string    `json:"token_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	MaxRequests int       `json:"max_requests,omitempty"`
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request, p *principal) {
	if !b.tokLim.Allow(p.id.Name) {
		b.metrics.inc("rate_limited_total")
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var req tokenRequest
	if err := decodeJSON(w, r, &req, 4<<10); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	key := "upstream:" + req.Upstream
	if (req.Upstream == "") == (req.Secret == "") {
		writeErr(w, http.StatusBadRequest, "specify exactly one of upstream or secret")
		return
	} else if req.Secret != "" {
		key = "secret:" + req.Secret
	}
	g, ok := b.policy.Load().Grant(p.id.Name, key)
	if !ok {
		b.deny(p, "token "+key, "no grant")
		writeErr(w, http.StatusForbidden, "not permitted by policy")
		return
	}
	ttl := g.MaxTTL.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid ttl")
			return
		}
		ttl = min(ttl, d) // agents may only ask for less, never more
	}
	now := b.now()
	c := token.Claims{
		ID: token.NewID(), Subject: p.id.Name, Grant: key,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
		CertThumb: p.thumb, MaxRequests: g.MaxRequests,
	}
	tok, err := b.issuer.Mint(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	purpose := truncate(req.Purpose, 200)
	if err := b.cfg.Audit.Append(p.id.String(), "token.issue", key, fmt.Sprintf("ok jti=%s ttl=%s purpose=%q", c.ID, ttl, purpose)); err != nil {
		b.auditFailure(w, err)
		return
	}
	b.metrics.inc("tokens_issued_total")
	writeJSON(w, http.StatusOK, tokenResponse{Token: tok, TokenID: c.ID,
		ExpiresAt: time.Unix(c.ExpiresAt, 0).UTC(), MaxRequests: c.MaxRequests})
}

// authorizeToken validates a bearer token for this principal and grant
// and consumes one unit of its request budget.
func (b *Broker) authorizeToken(r *http.Request, p *principal, key string) (*token.Claims, *policy.Grant, int, string) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, nil, http.StatusUnauthorized, "missing bearer token"
	}
	c, err := b.issuer.Verify(raw)
	if err != nil {
		return nil, nil, http.StatusUnauthorized, err.Error()
	}
	// Sender constraint: token must be presented over the same cert it was issued to.
	if c.Subject != p.id.Name || c.CertThumb != p.thumb {
		return nil, nil, http.StatusUnauthorized, "token not bound to this client certificate"
	}
	if c.Grant != key {
		return nil, nil, http.StatusForbidden, "token scope mismatch"
	}
	g, ok := b.policy.Load().Grant(p.id.Name, key)
	if !ok {
		return nil, nil, http.StatusForbidden, "grant no longer in policy"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, gone := b.revoked[c.ID]; gone {
		return nil, nil, http.StatusUnauthorized, "token revoked"
	}
	u := b.usage[c.ID]
	if u == nil {
		u = &usage{exp: c.ExpiresAt}
		b.usage[c.ID] = u
	}
	if c.MaxRequests > 0 && u.used >= c.MaxRequests {
		return nil, nil, http.StatusTooManyRequests, "token request budget exhausted"
	}
	u.used++
	return c, g, 0, ""
}

// --- agent: proxy -------------------------------------------------------

func (b *Broker) handleProxy(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("upstream")
	action := "proxy:" + name
	upPath := "/" + r.PathValue("rest")
	target := r.Method + " " + upPath

	if !b.proxyLim.Allow(p.id.Name) {
		b.metrics.inc("rate_limited_total")
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	// Reject encoded separators / traversal that could make the allowlist
	// check and the upstream's interpretation of the path diverge.
	if !safePath(r.URL.EscapedPath(), upPath) {
		b.deny(p, action+" "+target, "unsafe path")
		writeErr(w, http.StatusBadRequest, "unsafe path")
		return
	}
	c, g, code, why := b.authorizeToken(r, p, "upstream:"+name)
	if code != 0 {
		b.deny(p, action+" "+target, why)
		writeErr(w, code, why)
		return
	}
	if !g.Permits(r.Method, upPath) {
		b.deny(p, action+" "+target, "method/path not allowed")
		writeErr(w, http.StatusForbidden, "endpoint not allowed by policy")
		return
	}
	up := b.policy.Load().Upstreams[name]
	secret, err := b.cfg.Vault.Get(up.Secret)
	if err != nil {
		b.log.Error("secret unavailable", "secret", up.Secret, "err", err)
		writeErr(w, http.StatusBadGateway, "upstream credential unavailable")
		return
	}
	// Fail closed: if we cannot record the access, we do not perform it.
	if err := b.cfg.Audit.Append(p.id.String(), action, target, "forward jti="+c.ID); err != nil {
		b.auditFailure(w, err)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, b.cfg.MaxBodyBytes)
	start := b.now()
	rp := &httputil.ReverseProxy{
		Transport:     b.transport,
		FlushInterval: -1, // stream SSE / chunked LLM responses immediately
		Rewrite: func(pr *httputil.ProxyRequest) {
			u := *up.URL
			u.Path = up.URL.Path + upPath
			u.RawPath = ""
			u.RawQuery = pr.In.URL.RawQuery
			pr.Out.URL = &u
			pr.Out.Host = u.Host
			for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Real-Ip"} {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set(up.Inject.Header, up.Inject.Value(string(secret)))
			// Compressed bodies would defeat response redaction.
			pr.Out.Header.Set("Accept-Encoding", "identity")
		},
		ModifyResponse: func(resp *http.Response) error {
			if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
				return fmt.Errorf("upstream ignored identity encoding (%s)", ce)
			}
			resp.Header.Del("Set-Cookie")
			resp.Body = newRedactor(resp.Body, secret)
			b.metrics.inc(fmt.Sprintf(`proxy_responses_total{upstream=%q,code="%d"}`, name, resp.StatusCode))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			b.log.Warn("upstream error", "upstream", name, "agent", p.id.Name, "err", err)
			b.metrics.inc("proxy_errors_total")
			writeErr(w, http.StatusBadGateway, "upstream request failed")
		},
	}
	rp.ServeHTTP(w, r)
	b.log.Info("proxied", "agent", p.id.Name, "upstream", name, "req", target,
		"jti", c.ID, "dur_ms", b.now().Sub(start).Milliseconds())
}

func safePath(escaped, decoded string) bool {
	low := strings.ToLower(escaped)
	for _, bad := range []string{"%2f", "%5c", "%2e", "%00"} {
		if strings.Contains(low, bad) {
			return false
		}
	}
	return !strings.Contains(decoded, "..") && !strings.Contains(decoded, "//") && !strings.ContainsAny(decoded, "\\\x00")
}

// --- agent: reveal ------------------------------------------------------

func (b *Broker) handleReveal(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("name")
	key := "secret:" + name
	c, _, code, why := b.authorizeToken(r, p, key)
	if code != 0 {
		b.deny(p, "reveal "+name, why)
		writeErr(w, code, why)
		return
	}
	v, err := b.cfg.Vault.Get(name)
	if errors.Is(err, vault.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := b.cfg.Audit.Append(p.id.String(), "reveal", name, "ok jti="+c.ID); err != nil {
		b.auditFailure(w, err)
		return
	}
	b.metrics.inc("reveals_total")
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "value": string(v)})
}

// --- admin --------------------------------------------------------------

func (b *Broker) handleAdminList(w http.ResponseWriter, r *http.Request, p *principal) {
	b.cfg.Audit.Append(p.id.String(), "admin.list", "", "ok")
	writeJSON(w, http.StatusOK, map[string][]string{"secrets": b.cfg.Vault.List()})
}

func (b *Broker) handleAdminPut(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("name")
	v, err := io.ReadAll(http.MaxBytesReader(w, r.Body, vault.MaxSecretSize))
	if err != nil || len(v) == 0 {
		writeErr(w, http.StatusBadRequest, "secret body must be 1..64KiB")
		return
	}
	if err := b.cfg.Vault.Put(name, v); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, vault.ErrInvalidName) {
			code = http.StatusBadRequest
		}
		writeErr(w, code, err.Error())
		return
	}
	b.cfg.Audit.Append(p.id.String(), "admin.put", name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (b *Broker) handleAdminDelete(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("name")
	if err := b.cfg.Vault.Delete(name); errors.Is(err, vault.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	b.cfg.Audit.Append(p.id.String(), "admin.delete", name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (b *Broker) handleAdminRevoke(w http.ResponseWriter, r *http.Request, p *principal) {
	var req struct {
		TokenID string `json:"token_id"`
	}
	if err := decodeJSON(w, r, &req, 1<<10); err != nil || req.TokenID == "" {
		writeErr(w, http.StatusBadRequest, "token_id required")
		return
	}
	b.mu.Lock()
	b.revoked[req.TokenID] = b.now().Add(policy.MaxTTLCeiling).Unix()
	b.mu.Unlock()
	b.cfg.Audit.Append(p.id.String(), "admin.revoke", req.TokenID, "ok")
	b.metrics.inc("tokens_revoked_total")
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ------------------------------------------------------------

func (b *Broker) deny(p *principal, target, why string) {
	b.metrics.inc("denied_total")
	if err := b.cfg.Audit.Append(p.id.String(), "deny", target, why); err != nil {
		b.log.Error("audit append failed", "err", err)
	}
	b.log.Warn("denied", "principal", p.id.String(), "target", target, "reason", why)
}

func (b *Broker) auditFailure(w http.ResponseWriter, err error) {
	b.log.Error("audit append failed; refusing request", "err", err)
	writeErr(w, http.StatusServiceUnavailable, "audit unavailable")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
