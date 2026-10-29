package policy

import (
	"strings"
	"testing"
)

const good = `{
 "upstreams": {"openai": {"base_url": "https://api.openai.com", "secret": "openai-key",
   "inject": {"header": "authorization", "format": "Bearer {secret}"}}},
 "agents": {"yata": {"grants": [
   {"upstream": "openai", "max_ttl": "15m", "max_requests": 100,
    "allow": [{"method": "post", "path": "/v1/chat/completions"}, {"method": "GET", "path": "/v1/models/*"}]},
   {"secret": "db-password", "max_ttl": "5m"}]}}}`

func TestParseAndMatch(t *testing.T) {
	p, err := Parse(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	g, ok := p.Grant("yata", "upstream:openai")
	if !ok {
		t.Fatal("grant missing")
	}
	cases := []struct {
		m, path string
		want    bool
	}{
		{"POST", "/v1/chat/completions", true},
		{"GET", "/v1/chat/completions", false},
		{"POST", "/v1/chat/completions/x", false},
		{"GET", "/v1/models/gpt-5", true},
		{"GET", "/v1/models", false},
		{"DELETE", "/v1/models/gpt-5", false},
	}
	for _, c := range cases {
		if got := g.Permits(c.m, c.path); got != c.want {
			t.Errorf("Permits(%s %s) = %v", c.m, c.path, got)
		}
	}
	if _, ok := p.Grant("other", "upstream:openai"); ok {
		t.Fatal("default deny violated")
	}
}

func TestRejectsUnsafePolicies(t *testing.T) {
	bad := map[string]string{
		"http upstream":   strings.Replace(good, "https://api.openai.com", "http://api.openai.com", 1),
		"unknown field":   strings.Replace(good, `"max_ttl": "5m"`, `"max_ttl": "5m", "allow_all": true`, 1),
		"ttl too long":    strings.Replace(good, `"15m"`, `"48h"`, 1),
		"host injection":  strings.Replace(good, `"authorization"`, `"Host"`, 1),
		"crlf in format":  strings.Replace(good, `Bearer {secret}`, `Bearer {secret}\r\nX: y`, 1),
		"path traversal":  strings.Replace(good, `/v1/chat/completions`, `/v1/../admin`, 1),
		"mid wildcard":    strings.Replace(good, `/v1/models/*`, `/v1/*/models`, 1),
		"no secret token": strings.Replace(good, `Bearer {secret}`, `Bearer`, 1),
	}
	for name, src := range bad {
		if _, err := Parse(strings.NewReader(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
