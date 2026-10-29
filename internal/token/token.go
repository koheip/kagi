// Package token mints and verifies short-lived, sender-constrained
// capability tokens.
//
// Format:  kagi_v1.<base64url(JSON claims)>.<base64url(Ed25519 signature)>
//
// Every token is bound to the SHA-256 thumbprint of the agent's mTLS client
// certificate (the "cnf" claim, as in RFC 8705). A token that leaks through
// a prompt-injected log, a pasted transcript or a compromised tool output is
// useless without the agent's private key.
package token

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	prefix  = "kagi_v1."
	maxLen  = 4096
	version = 1
)

var (
	ErrMalformed = errors.New("token: malformed")
	ErrSignature = errors.New("token: bad signature")
	ErrExpired   = errors.New("token: expired")
)

var b64 = base64.RawURLEncoding.Strict() // reject non-canonical encodings (no malleability)

type Claims struct {
	Version     int    `json:"v"`
	ID          string `json:"jti"`
	Subject     string `json:"sub"`   // agent name
	Grant       string `json:"grant"` // "upstream:<name>" or "secret:<name>"
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	CertThumb   string `json:"cnf"`           // x5t#S256 of the client cert
	MaxRequests int    `json:"max,omitempty"` // 0 = unlimited within TTL
}

// Issuer signs with an in-memory key generated at startup. Restarting the
// broker therefore revokes every outstanding token, which is acceptable
// (and desirable) for tokens that live minutes.
type Issuer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	now  func() time.Time
}

func NewIssuer() *Issuer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Issuer{priv: priv, pub: pub, now: time.Now}
}

func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (i *Issuer) Mint(c Claims) (string, error) {
	c.Version = version
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := prefix + b64.EncodeToString(payload)
	sig := ed25519.Sign(i.priv, []byte(signing))
	return signing + "." + b64.EncodeToString(sig), nil
}

func (i *Issuer) Verify(tok string) (*Claims, error) {
	if len(tok) > maxLen || !strings.HasPrefix(tok, prefix) {
		return nil, ErrMalformed
	}
	dot := strings.LastIndexByte(tok, '.')
	if dot <= len(prefix) {
		return nil, ErrMalformed
	}
	sig, err := b64.DecodeString(tok[dot+1:])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	// Verify the signature before parsing anything attacker-controlled.
	if !ed25519.Verify(i.pub, []byte(tok[:dot]), sig) {
		return nil, ErrSignature
	}
	payload, err := b64.DecodeString(tok[len(prefix):dot])
	if err != nil {
		return nil, ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var c Claims
	if err := dec.Decode(&c); err != nil || c.Version != version || c.ID == "" || c.CertThumb == "" {
		return nil, ErrMalformed
	}
	if i.now().Unix() >= c.ExpiresAt {
		return nil, ErrExpired
	}
	return &c, nil
}
