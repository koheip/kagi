// Package policy defines which agent may use which secret, and how.
//
// Default deny: an agent with no matching grant gets nothing, and an
// upstream grant only permits the listed method + path combinations.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// MaxTTLCeiling is the hard upper bound for any token lifetime.
const MaxTTLCeiling = time.Hour

var (
	headerToken = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	forbiddenHd = map[string]bool{"Host": true, "Connection": true, "Content-Length": true,
		"Transfer-Encoding": true, "Te": true, "Upgrade": true, "Cookie": true}
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

type Inject struct {
	Header string `json:"header"`
	Format string `json:"format"` // must contain "{secret}" exactly once
}

func (i Inject) Value(secret string) string { return strings.Replace(i.Format, "{secret}", secret, 1) }

type Upstream struct {
	BaseURL string   `json:"base_url"`
	Secret  string   `json:"secret"`
	Inject  Inject   `json:"inject"`
	URL     *url.URL `json:"-"`
}

type Rule struct {
	Method string `json:"method"`
	Path   string `json:"path"` // exact, or prefix when ending in "/*"
}

func (r Rule) match(method, path string) bool {
	if r.Method != method {
		return false
	}
	if p, ok := strings.CutSuffix(r.Path, "/*"); ok {
		return strings.HasPrefix(path, p+"/")
	}
	return path == r.Path
}

type Grant struct {
	Upstream    string   `json:"upstream,omitempty"`
	Secret      string   `json:"secret,omitempty"` // "reveal" grant: raw value
	Allow       []Rule   `json:"allow,omitempty"`
	MaxTTL      Duration `json:"max_ttl"`
	MaxRequests int      `json:"max_requests,omitempty"`
}

func (g *Grant) Key() string {
	if g.Upstream != "" {
		return "upstream:" + g.Upstream
	}
	return "secret:" + g.Secret
}

func (g *Grant) Permits(method, path string) bool {
	for _, r := range g.Allow {
		if r.match(method, path) {
			return true
		}
	}
	return false
}

type Agent struct {
	Grants []*Grant `json:"grants"`
}

type Policy struct {
	Upstreams map[string]*Upstream `json:"upstreams"`
	Agents    map[string]*Agent    `json:"agents"`
}

// Grant returns the grant identified by key ("upstream:x" / "secret:x").
func (p *Policy) Grant(agent, key string) (*Grant, bool) {
	a, ok := p.Agents[agent]
	if !ok {
		return nil, false
	}
	for _, g := range a.Grants {
		if g.Key() == key {
			return g, true
		}
	}
	return nil, false
}

func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func Parse(r io.Reader) (*Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields() // typos must not silently widen access
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	for name, u := range p.Upstreams {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("invalid upstream name %q", name)
		}
		pu, err := url.Parse(u.BaseURL)
		if err != nil || pu.Scheme != "https" || pu.Host == "" || pu.User != nil || pu.RawQuery != "" || pu.Fragment != "" {
			return fmt.Errorf("upstream %q: base_url must be a plain https URL", name)
		}
		pu.Path = strings.TrimSuffix(pu.Path, "/")
		u.URL = pu
		if u.Secret == "" {
			return fmt.Errorf("upstream %q: secret required", name)
		}
		h := http.CanonicalHeaderKey(u.Inject.Header)
		if !headerToken.MatchString(h) || forbiddenHd[h] {
			return fmt.Errorf("upstream %q: invalid inject header %q", name, u.Inject.Header)
		}
		u.Inject.Header = h
		if strings.Count(u.Inject.Format, "{secret}") != 1 || strings.ContainsAny(u.Inject.Format, "\r\n") {
			return fmt.Errorf("upstream %q: inject.format must contain {secret} exactly once", name)
		}
	}
	for name, a := range p.Agents {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("invalid agent name %q", name)
		}
		seen := map[string]bool{}
		for _, g := range a.Grants {
			if (g.Upstream == "") == (g.Secret == "") {
				return fmt.Errorf("agent %q: each grant needs exactly one of upstream/secret", name)
			}
			if seen[g.Key()] {
				return fmt.Errorf("agent %q: duplicate grant %s", name, g.Key())
			}
			seen[g.Key()] = true
			if g.MaxTTL.Duration <= 0 || g.MaxTTL.Duration > MaxTTLCeiling {
				return fmt.Errorf("agent %q: max_ttl must be in (0, %s]", name, MaxTTLCeiling)
			}
			if g.MaxRequests < 0 {
				return errors.New("max_requests must be >= 0")
			}
			if g.Upstream != "" {
				if _, ok := p.Upstreams[g.Upstream]; !ok {
					return fmt.Errorf("agent %q: unknown upstream %q", name, g.Upstream)
				}
				if len(g.Allow) == 0 {
					return fmt.Errorf("agent %q: upstream grant %q needs at least one allow rule", name, g.Upstream)
				}
			} else if len(g.Allow) != 0 {
				return fmt.Errorf("agent %q: secret grants take no allow rules", name)
			}
			for i := range g.Allow {
				r := &g.Allow[i]
				r.Method = strings.ToUpper(r.Method)
				if !headerToken.MatchString(r.Method) {
					return fmt.Errorf("agent %q: bad method %q", name, r.Method)
				}
				if !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "..") || strings.Contains(r.Path, "//") ||
					(strings.Contains(r.Path, "*") && !strings.HasSuffix(r.Path, "/*")) {
					return fmt.Errorf("agent %q: bad path %q", name, r.Path)
				}
			}
		}
	}
	return nil
}
