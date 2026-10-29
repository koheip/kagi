package pki

import (
	"net/url"
	"testing"
	"time"
)

func TestIdentityRoundTrip(t *testing.T) {
	ca, err := NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := ca.Issue(KindAgent, "yata", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityFromCert(c)
	if err != nil || id != (Identity{KindAgent, "yata"}) {
		t.Fatalf("%v %v", id, err)
	}
	if len(Thumbprint(c)) != 64 {
		t.Fatal("thumbprint should be hex SHA-256")
	}
}

func TestRejectsBadIdentities(t *testing.T) {
	ca, _ := NewCA(time.Hour)
	srv, _, _ := ca.Issue(KindServer, "broker", []string{"localhost"}, time.Hour)
	if _, err := IdentityFromCert(srv); err == nil {
		t.Fatal("server cert must not be usable as a client identity")
	}
	c, _, _ := ca.Issue(KindAgent, "yata", nil, time.Hour)
	for _, u := range []string{"spiffe://evil.example/agent/yata", "spiffe://kagi.local/server/x",
		"spiffe://kagi.local/agent/../admin/ops", "https://kagi.local/agent/yata"} {
		c.URIs = []*url.URL{mustURL(u)}
		if _, err := IdentityFromCert(c); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
	if _, _, err := ca.Issue(KindAgent, "Bad Name", nil, time.Hour); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
