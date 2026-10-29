// Command kagid runs the kagi secret broker.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/koheip/kagi/internal/audit"
	"github.com/koheip/kagi/internal/broker"
	"github.com/koheip/kagi/internal/pki"
	"github.com/koheip/kagi/internal/policy"
	"github.com/koheip/kagi/internal/vault"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kagid:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen       = flag.String("listen", ":8443", "mTLS API listen address")
		opsListen    = flag.String("ops-listen", "127.0.0.1:9090", "metrics/health listen address (\"\" to disable)")
		certFile     = flag.String("tls-cert", "pki/broker.crt", "server certificate")
		keyFile      = flag.String("tls-key", "pki/broker.key", "server private key")
		caFile       = flag.String("client-ca", "pki/ca.crt", "CA that signs agent/admin certificates")
		policyFile   = flag.String("policy", "policy.json", "access policy (reloaded on SIGHUP)")
		vaultFile    = flag.String("vault", "data/vault.json", "encrypted vault file")
		auditFile    = flag.String("audit", "data/audit.log", "tamper-evident audit log")
		pqOnly       = flag.Bool("pq-only", false, "accept only the X25519MLKEM768 post-quantum hybrid key exchange")
		allowPrivate = flag.Bool("dev-allow-private-upstreams", false, "DEV ONLY: disable SSRF egress guard")
		verifyAudit  = flag.Bool("verify-audit", false, "verify the audit log chain and exit")
		upstreamCA   = flag.String("dev-upstream-ca", "", "DEV ONLY: extra CA bundle trusted for upstream TLS")
	)
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	v, err := vault.Open(*vaultFile, pass)
	if err != nil {
		return err
	}

	if *verifyAudit {
		f, err := os.Open(*auditFile)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := audit.Verify(f, v.AuditKey())
		if err != nil {
			return err
		}
		fmt.Printf("audit log OK: %d entries, chain intact\n", n)
		return nil
	}

	al, err := audit.Open(*auditFile, v.AuditKey())
	if err != nil {
		return err
	}
	defer al.Close()
	pol, err := policy.Load(*policyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	clientCAs, err := pki.LoadPool(*caFile)
	if err != nil {
		return err
	}
	if *allowPrivate {
		log.Warn("SSRF egress guard DISABLED (dev mode)")
	}

	cfg := broker.Config{Policy: pol, Vault: v, Audit: al, Logger: log, AllowPrivateUpstreams: *allowPrivate}
	if *upstreamCA != "" {
		if cfg.UpstreamRootCAs, err = pki.LoadPool(*upstreamCA); err != nil {
			return err
		}
	}
	b, err := broker.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go b.RunJanitor(ctx)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			p, err := policy.Load(*policyFile)
			if err != nil {
				log.Error("policy reload failed; keeping previous policy", "err", err)
				continue
			}
			b.SetPolicy(p)
			al.Append("system", "policy.reload", *policyFile, "ok")
			log.Info("policy reloaded")
		}
	}()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           b.Handler(),
		TLSConfig:         broker.ServerTLSConfig(cert, clientCAs, *pqOnly),
		ReadHeaderTimeout: 5 * time.Second, // slowloris
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()

	var ops *http.Server
	if *opsListen != "" {
		ops = &http.Server{Addr: *opsListen, Handler: b.OpsHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() { errc <- ops.ListenAndServe() }()
	}
	log.Info("kagid started", "listen", *listen, "ops", *opsListen, "pq_only", *pqOnly,
		"agents", len(pol.Agents), "upstreams", len(pol.Upstreams))

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if ops != nil {
		ops.Shutdown(sctx)
	}
	return srv.Shutdown(sctx)
}

// readPassphrase prefers a file (Docker/K8s secret mount) over an env var,
// and scrubs the env var so child processes / crash dumps don't inherit it.
func readPassphrase() (string, error) {
	if p := os.Getenv("KAGI_PASSPHRASE_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if p := os.Getenv("KAGI_PASSPHRASE"); p != "" {
		os.Unsetenv("KAGI_PASSPHRASE")
		return p, nil
	}
	return "", errors.New("set KAGI_PASSPHRASE_FILE (recommended) or KAGI_PASSPHRASE")
}
