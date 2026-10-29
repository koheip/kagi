// Package pki is a minimal private CA for issuing mTLS certificates.
//
// Identities are encoded as SPIFFE-style URI SANs:
//
//	spiffe://kagi.local/agent/<name>   – an AI agent / workload
//	spiffe://kagi.local/admin/<name>   – an operator
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const TrustDomain = "kagi.local"

type Kind string

const (
	KindServer Kind = "server"
	KindAgent  Kind = "agent"
	KindAdmin  Kind = "admin"
)

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Identity is the authenticated principal behind a client certificate.
type Identity struct {
	Kind Kind
	Name string
}

func (id Identity) String() string { return string(id.Kind) + "/" + id.Name }

func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/" + string(id.Kind) + "/" + id.Name}
}

// IdentityFromCert extracts exactly one kagi identity from a verified cert.
func IdentityFromCert(c *x509.Certificate) (Identity, error) {
	if len(c.URIs) != 1 {
		return Identity{}, errors.New("pki: certificate must carry exactly one URI SAN")
	}
	u := c.URIs[0]
	if u.Scheme != "spiffe" || u.Host != TrustDomain {
		return Identity{}, fmt.Errorf("pki: foreign identity %q", u)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || !validName.MatchString(parts[1]) {
		return Identity{}, fmt.Errorf("pki: malformed identity %q", u)
	}
	switch k := Kind(parts[0]); k {
	case KindAgent, KindAdmin:
		return Identity{Kind: k, Name: parts[1]}, nil
	default:
		return Identity{}, fmt.Errorf("pki: identity kind %q cannot be a client", k)
	}
}

// Thumbprint is the RFC 8705 "x5t#S256" value used to bind tokens to a cert.
func Thumbprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func NewCA(validity time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "kagi root CA", Organization: []string{"kagi"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return &CA{Cert: cert, Key: key}, err
}

// Issue creates a leaf certificate. Server certs get DNS/IP SANs and
// serverAuth; client certs get a SPIFFE URI and clientAuth only.
func (ca *CA) Issue(kind Kind, name string, hosts []string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if !validName.MatchString(name) {
		return nil, nil, fmt.Errorf("pki: invalid name %q", name)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"kagi"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	switch kind {
	case KindServer:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
	case KindAgent, KindAdmin:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tmpl.URIs = []*url.URL{Identity{Kind: kind, Name: name}.URI()}
	default:
		return nil, nil, fmt.Errorf("pki: unknown kind %q", kind)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// --- PEM helpers ---------------------------------------------------------

func WriteCert(path string, c *x509.Certificate) error {
	return writePEM(path, "CERTIFICATE", c.Raw, 0o644)
}

func WriteKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	// O_EXCL: never silently overwrite existing key material.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func LoadCA(certPath, keyPath string) (*CA, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, errors.New("pki: invalid PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: CA key must be ECDSA")
	}
	return &CA{Cert: cert, Key: ek}, nil
}

// LoadPool reads a PEM bundle into a cert pool.
func LoadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("pki: no certificates in %s", path)
	}
	return p, nil
}
