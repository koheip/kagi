// Command kagictl is a small client for operators (and for testing agents).
//
//	kagictl secret put NAME      # value read from stdin (never from argv / shell history)
//	kagictl secret rm NAME
//	kagictl secret ls
//	kagictl revoke TOKEN_ID
//	kagictl token UPSTREAM       # as an agent: print a short-lived token
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	var (
		base = flag.String("url", env("KAGI_URL", "https://localhost:8443"), "broker URL")
		cert = flag.String("cert", env("KAGI_CERT", "pki/ops.crt"), "client certificate")
		key  = flag.String("key", env("KAGI_KEY", "pki/ops.key"), "client key")
		ca   = flag.String("ca", env("KAGI_CA", "pki/ca.crt"), "CA certificate")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		die("usage: kagictl [flags] secret put|rm|ls NAME | revoke ID | token UPSTREAM")
	}
	c := client(*cert, *key, *ca)
	switch {
	case len(args) == 3 && args[0] == "secret" && args[1] == "put":
		v, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10+1))
		check(err)
		call(c, "PUT", *base+"/v1/admin/secrets/"+url.PathEscape(args[2]), bytes.TrimRight(v, "\r\n"))
	case len(args) == 3 && args[0] == "secret" && args[1] == "rm":
		call(c, "DELETE", *base+"/v1/admin/secrets/"+url.PathEscape(args[2]), nil)
	case len(args) == 2 && args[0] == "secret" && args[1] == "ls":
		call(c, "GET", *base+"/v1/admin/secrets", nil)
	case len(args) == 2 && args[0] == "revoke":
		b, _ := json.Marshal(map[string]string{"token_id": args[1]})
		call(c, "POST", *base+"/v1/admin/revoke", b)
	case len(args) == 2 && args[0] == "token":
		b, _ := json.Marshal(map[string]string{"upstream": args[1], "purpose": "kagictl"})
		call(c, "POST", *base+"/v1/token", b)
	default:
		die("unknown command")
	}
}

func client(certFile, keyFile, caFile string) *http.Client {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	check(err)
	pem, err := os.ReadFile(caFile)
	check(err)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair},
	}}}
}

func call(c *http.Client, method, u string, body []byte) {
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	check(err)
	resp, err := c.Do(req)
	check(err)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		die(fmt.Sprintf("%s: %s", resp.Status, bytes.TrimSpace(out)))
	}
	if len(out) == 0 {
		fmt.Println("ok")
		return
	}
	os.Stdout.Write(out)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func check(err error) {
	if err != nil {
		die(err.Error())
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "kagictl:", msg)
	os.Exit(1)
}
