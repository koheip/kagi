package broker

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/koheip/kagi/internal/audit"
	"github.com/koheip/kagi/internal/pki"
	"github.com/koheip/kagi/internal/policy"
	"github.com/koheip/kagi/internal/vault"
)

const fakeKey = "sk-test-SUPERSECRET-0123456789"

type env struct {
	t        *testing.T
	ca       *pki.CA
	broker   *Broker
	srv      *httptest.Server
	upHits   atomic.Int64
	lastAuth atomic.Value
	auditLog string
	auditKey []byte
}

func policyJSON(upstreamURL string) string {
	return fmt.Sprintf(`{
 "upstreams": {"openai": {"base_url": %q, "secret": "openai-key",
   "inject": {"header": "Authorization", "format": "Bearer {secret}"}}},
 "agents": {
   "yata": {"grants": [
     {"upstream": "openai", "max_ttl": "10m", "max_requests": 5,
      "allow": [{"method": "POST", "path": "/v1/chat/completions"}, {"method": "GET", "path": "/v1/echo"}]},
     {"secret": "db-password", "max_ttl": "1m"}]},
   "evil": {"grants": []}
 }}`, upstreamURL)
}

func setup(t *testing.T, allowPrivate, pqOnly bool) *env {
	t.Helper()
	vault.DefaultIterations, vault.MinIterations = 1000, 1000
	e := &env{t: t}
	e.lastAuth.Store("")

	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.upHits.Add(1)
		e.lastAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "upstream-session=1")
		if r.URL.Path == "/v1/echo" { // a misbehaving upstream that leaks the key
			fmt.Fprintf(w, `{"debug":"you sent %s"}`, r.Header.Get("Authorization"))
			return
		}
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	t.Cleanup(up.Close)

	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault.json"), "pass")
	if err != nil {
		t.Fatal(err)
	}
	v.Put("openai-key", []byte(fakeKey))
	v.Put("db-password", []byte("hunter2"))
	e.auditLog = filepath.Join(dir, "audit.log")
	e.auditKey = v.AuditKey()
	al, err := audit.Open(e.auditLog, e.auditKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })

	pol, err := policy.Parse(strings.NewReader(policyJSON(up.URL)))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	e.broker, err = New(Config{Policy: pol, Vault: v, Audit: al, AllowPrivateUpstreams: allowPrivate,
		UpstreamRootCAs: roots, TokenRate: 100, TokenBurst: 100, ProxyRate: 100, ProxyBurst: 100})
	if err != nil {
		t.Fatal(err)
	}

	e.ca, _ = pki.NewCA(time.Hour)
	sc, sk, _ := e.ca.Issue(pki.KindServer, "broker", []string{"127.0.0.1"}, time.Hour)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(e.ca.Cert)
	e.srv = httptest.NewUnstartedServer(e.broker.Handler())
	e.srv.TLS = ServerTLSConfig(tls.Certificate{Certificate: [][]byte{sc.Raw}, PrivateKey: sk}, clientCAs, pqOnly)
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) client(kind pki.Kind, name string, mod ...func(*tls.Config)) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Cert)
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if name != "" {
		c, k, err := e.ca.Issue(kind, name, nil, time.Hour)
		if err != nil {
			e.t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{c.Raw}, PrivateKey: k}}
	}
	for _, m := range mod {
		m(cfg)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func (e *env) do(c *http.Client, method, path, bearer, body string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Set-Cookie") != "" {
		e.t.Error("upstream Set-Cookie leaked to agent")
	}
	return resp.StatusCode, string(b)
}

func (e *env) token(c *http.Client, req string) (string, string) {
	e.t.Helper()
	code, body := e.do(c, "POST", "/v1/token", "", req)
	if code != 200 {
		e.t.Fatalf("token: %d %s", code, body)
	}
	var tr tokenResponse
	json.Unmarshal([]byte(body), &tr)
	return tr.Token, tr.TokenID
}

const chat = "/v1/proxy/openai/v1/chat/completions"

func TestAgentNeverSeesKey(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	tok, _ := e.token(yata, `{"upstream":"openai","ttl":"2m","purpose":"answer user question"}`)
	if strings.Contains(tok, fakeKey) {
		t.Fatal("token contains the key")
	}
	code, body := e.do(yata, "POST", chat, tok, `{"model":"x"}`)
	if code != 200 || !strings.Contains(body, `/v1/chat/completions`) {
		t.Fatalf("%d %s", code, body)
	}
	if got := e.lastAuth.Load().(string); got != "Bearer "+fakeKey {
		t.Fatalf("upstream got Authorization %q", got)
	}
}

func TestResponseRedaction(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	tok, _ := e.token(yata, `{"upstream":"openai"}`)
	code, body := e.do(yata, "GET", "/v1/proxy/openai/v1/echo", tok, "")
	if code != 200 || strings.Contains(body, fakeKey) || !strings.Contains(body, "*****") {
		t.Fatalf("key leaked or not masked: %d %s", code, body)
	}
}

func TestAllowlistAndPathTricks(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	tok, _ := e.token(yata, `{"upstream":"openai"}`)
	for _, tc := range []struct {
		m, p string
		want int
	}{
		{"DELETE", chat, 403},
		{"POST", "/v1/proxy/openai/v1/files", 403},
		{"POST", "/v1/proxy/openai/v1/chat%2Fcompletions", 400},
		{"POST", "/v1/proxy/openai/v1/chat/completions/..%2f..%2fadmin", 400},
		{"POST", "/v1/proxy/other/v1/chat/completions", 403},
	} {
		if code, body := e.do(yata, tc.m, tc.p, tok, ""); code != tc.want {
			t.Errorf("%s %s = %d %s, want %d", tc.m, tc.p, code, body, tc.want)
		}
	}
	if e.upHits.Load() != 0 {
		t.Fatal("denied requests must never reach the upstream")
	}
}

func TestStolenTokenIsUseless(t *testing.T) {
	e := setup(t, true, false)
	tok, _ := e.token(e.client(pki.KindAgent, "yata"), `{"upstream":"openai"}`)
	// Different agent, and even the *same* agent name with a different cert.
	for _, thief := range []*http.Client{e.client(pki.KindAgent, "evil"), e.client(pki.KindAgent, "yata")} {
		if code, _ := e.do(thief, "POST", chat, tok, ""); code != 401 {
			t.Fatalf("stolen token accepted: %d", code)
		}
	}
}

func TestBudgetRevokeAndPolicyReload(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	admin := e.client(pki.KindAdmin, "ops")

	tok, _ := e.token(yata, `{"upstream":"openai"}`)
	for i := 0; i < 5; i++ {
		if code, _ := e.do(yata, "POST", chat, tok, ""); code != 200 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code, _ := e.do(yata, "POST", chat, tok, ""); code != 429 {
		t.Fatalf("budget not enforced: %d", code)
	}

	tok2, id2 := e.token(yata, `{"upstream":"openai"}`)
	if code, _ := e.do(admin, "POST", "/v1/admin/revoke", "", `{"token_id":"`+id2+`"}`); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := e.do(yata, "POST", chat, tok2, ""); code != 401 {
		t.Fatalf("revoked token accepted: %d", code)
	}

	tok3, _ := e.token(yata, `{"upstream":"openai"}`)
	empty, _ := policy.Parse(strings.NewReader(`{"upstreams":{},"agents":{}}`))
	e.broker.SetPolicy(empty)
	if code, _ := e.do(yata, "POST", chat, tok3, ""); code != 403 {
		t.Fatalf("token survived policy removal: %d", code)
	}
}

func TestRoleSeparation(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	admin := e.client(pki.KindAdmin, "ops")
	if code, _ := e.do(yata, "GET", "/v1/admin/secrets", "", ""); code != 403 {
		t.Fatalf("agent reached admin API: %d", code)
	}
	if code, _ := e.do(admin, "POST", "/v1/token", "", `{"upstream":"openai"}`); code != 403 {
		t.Fatalf("admin got agent token: %d", code)
	}
	if code, _ := e.do(e.client(pki.KindAgent, "evil"), "POST", "/v1/token", "", `{"upstream":"openai"}`); code != 403 {
		t.Fatalf("ungranted agent got token: %d", code)
	}
	if code, _ := e.do(yata, "POST", "/v1/token", "", `{"upstream":"openai","ttl":"999h"}`); code != 200 {
		t.Fatal("ttl request should be clamped, not rejected")
	}
}

func TestRevealGrant(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	tok, _ := e.token(yata, `{"secret":"db-password"}`)
	code, body := e.do(yata, "GET", "/v1/secrets/db-password", tok, "")
	if code != 200 || !strings.Contains(body, "hunter2") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := e.do(yata, "GET", "/v1/secrets/openai-key", tok, ""); code != 403 {
		t.Fatalf("reveal outside grant: %d", code)
	}
}

func TestMTLSRequired(t *testing.T) {
	e := setup(t, true, false)
	anon := e.client(pki.KindAgent, "")
	if _, err := anon.Get(e.srv.URL + "/v1/admin/secrets"); err == nil {
		t.Fatal("connection without client cert must fail the TLS handshake")
	}
	// A cert from a different CA must also be rejected.
	rogue, _ := pki.NewCA(time.Hour)
	rc, rk, _ := rogue.Issue(pki.KindAdmin, "ops", nil, time.Hour)
	c := e.client(pki.KindAdmin, "", func(cfg *tls.Config) {
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{rc.Raw}, PrivateKey: rk}}
	})
	if _, err := c.Get(e.srv.URL + "/v1/admin/secrets"); err == nil {
		t.Fatal("rogue CA accepted")
	}
}

func TestPostQuantumOnly(t *testing.T) {
	e := setup(t, true, true)
	classic := e.client(pki.KindAdmin, "ops", func(cfg *tls.Config) {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	})
	if _, err := classic.Get(e.srv.URL + "/v1/admin/secrets"); err == nil {
		t.Fatal("classical-only key exchange accepted in pq-only mode")
	}
	if code, _ := e.do(e.client(pki.KindAdmin, "ops"), "GET", "/v1/admin/secrets", "", ""); code != 200 {
		t.Fatal("hybrid X25519MLKEM768 client should succeed")
	}
}

func TestEgressGuardBlocksSSRF(t *testing.T) {
	e := setup(t, false, false) // upstream is on 127.0.0.1 => must be blocked
	yata := e.client(pki.KindAgent, "yata")
	tok, _ := e.token(yata, `{"upstream":"openai"}`)
	if code, _ := e.do(yata, "POST", chat, tok, ""); code != 502 {
		t.Fatalf("want 502, got %d", code)
	}
	if e.upHits.Load() != 0 {
		t.Fatal("request reached a loopback address")
	}
}

func TestAuditTrailIsIntact(t *testing.T) {
	e := setup(t, true, false)
	yata := e.client(pki.KindAgent, "yata")
	tok, _ := e.token(yata, `{"upstream":"openai"}`)
	e.do(yata, "POST", chat, tok, "")
	e.do(yata, "DELETE", chat, tok, "")
	raw, _ := os.ReadFile(e.auditLog)
	n, err := audit.Verify(bytes.NewReader(raw), e.auditKey)
	if err != nil || n < 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if bytes.Contains(raw, []byte(fakeKey)) || bytes.Contains(raw, []byte(tok)) {
		t.Fatal("audit log must not contain secrets or tokens")
	}
	for _, want := range []string{`"token.issue"`, `"proxy:openai"`, `"deny"`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("audit log missing %s", want)
		}
	}
}

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.0.1": false, "172.16.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "::1": false, "fe80::1": false,
		"::ffff:127.0.0.1": false, "0.0.0.0": false, "fd00::1": false,
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v", addr, got)
		}
	}
}

func TestRedactorAcrossReadBoundaries(t *testing.T) {
	secret := []byte("SECRET")
	in := "aSECRETbSECSECRETcSECRET"
	r := newRedactor(io.NopCloser(iotest.OneByteReader(strings.NewReader(in))), secret)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a******bSEC******c******"; string(out) != want {
		t.Fatalf("got %q want %q", out, want)
	}
}
