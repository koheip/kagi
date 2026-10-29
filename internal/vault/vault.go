// Package vault stores secrets encrypted at rest using envelope encryption:
//
//	passphrase --PBKDF2-SHA256--> master --HKDF--> KEK
//	KEK wraps a random per-secret DEK   (AES-256-GCM, AAD = "dek:"+name)
//	DEK encrypts the secret value       (AES-256-GCM, AAD = "secret:"+name)
//
// Binding the name into the AAD means an attacker with write access to the
// file cannot swap ciphertexts between entries. Changing the passphrase
// (Rekey) only re-wraps the small DEKs; the secret ciphertexts never change.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	formatVersion = 1
	kdfAlg        = "pbkdf2-sha256"
	saltLen       = 16
)

// DefaultIterations follows the OWASP 2023 recommendation for PBKDF2-SHA256.
// MinIterations rejects files whose work factor was tampered down.
var (
	DefaultIterations = 600_000
	MinIterations     = 100_000
)

var (
	ErrNotFound        = errors.New("vault: secret not found")
	ErrInvalidName     = errors.New("vault: invalid secret name")
	ErrWrongPassphrase = errors.New("vault: wrong passphrase or corrupted vault")
	ErrCorrupt         = errors.New("vault: integrity check failed")
	ErrTooLarge        = errors.New("vault: secret too large")
)

// MaxSecretSize keeps individual secrets small; this is a vault, not a blob store.
const MaxSecretSize = 64 << 10

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

type kdfParams struct {
	Alg        string `json:"alg"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
}

type record struct {
	WrappedDEK []byte    `json:"wrapped_dek"`
	Ciphertext []byte    `json:"ciphertext"`
	Updated    time.Time `json:"updated"`
}

type fileFormat struct {
	Version  int               `json:"version"`
	KDF      kdfParams         `json:"kdf"`
	AuditKey []byte            `json:"audit_key"` // random key, wrapped by KEK
	Secrets  map[string]record `json:"secrets"`
}

// Vault is safe for concurrent use.
type Vault struct {
	mu       sync.RWMutex
	path     string
	kek      cipher.AEAD
	auditKey []byte
	data     fileFormat
}

// Open loads the vault at path, creating it if it does not exist.
func Open(path, passphrase string) (*Vault, error) {
	if passphrase == "" {
		return nil, errors.New("vault: empty passphrase")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return create(path, passphrase)
	}
	if err != nil {
		return nil, err
	}

	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if f.Version != formatVersion || f.KDF.Alg != kdfAlg {
		return nil, fmt.Errorf("vault: unsupported format v%d/%s", f.Version, f.KDF.Alg)
	}
	if f.KDF.Iterations < MinIterations || len(f.KDF.Salt) < saltLen {
		return nil, fmt.Errorf("%w: weak KDF parameters", ErrCorrupt)
	}
	if f.Secrets == nil {
		f.Secrets = map[string]record{}
	}
	kek, err := deriveKEK(passphrase, f.KDF)
	if err != nil {
		return nil, err
	}
	// Unwrapping the audit key doubles as the passphrase check.
	auditKey, err := open(kek, f.AuditKey, []byte("audit-key"))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return &Vault{path: path, kek: kek, auditKey: auditKey, data: f}, nil
}

func create(path, passphrase string) (*Vault, error) {
	f := fileFormat{
		Version: formatVersion,
		KDF:     kdfParams{Alg: kdfAlg, Iterations: DefaultIterations, Salt: random(saltLen)},
		Secrets: map[string]record{},
	}
	kek, err := deriveKEK(passphrase, f.KDF)
	if err != nil {
		return nil, err
	}
	auditKey := random(32)
	f.AuditKey = seal(kek, auditKey, []byte("audit-key"))
	v := &Vault{path: path, kek: kek, auditKey: auditKey, data: f}
	if err := v.persist(); err != nil {
		return nil, err
	}
	return v, nil
}

func deriveKEK(passphrase string, p kdfParams) (cipher.AEAD, error) {
	master, err := pbkdf2.Key(sha256.New, passphrase, p.Salt, p.Iterations, 32)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	kek, err := hkdf.Key(sha256.New, master, nil, "kagi/v1 vault kek", 32)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	return newAEAD(kek)
}

// AuditKey returns the HMAC key used for the tamper-evident audit log.
func (v *Vault) AuditKey() []byte { return append([]byte(nil), v.auditKey...) }

func (v *Vault) Put(name string, value []byte) error {
	if !validName.MatchString(name) {
		return ErrInvalidName
	}
	if len(value) > MaxSecretSize {
		return ErrTooLarge
	}
	dek := random(32)
	defer clear(dek)
	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return err
	}
	rec := record{
		WrappedDEK: seal(v.kek, dek, []byte("dek:"+name)),
		Ciphertext: seal(dekAEAD, value, []byte("secret:"+name)),
		Updated:    time.Now().UTC(),
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	prev, existed := v.data.Secrets[name]
	v.data.Secrets[name] = rec
	if err := v.persist(); err != nil {
		if existed {
			v.data.Secrets[name] = prev
		} else {
			delete(v.data.Secrets, name)
		}
		return err
	}
	return nil
}

func (v *Vault) Get(name string) ([]byte, error) {
	if !validName.MatchString(name) {
		return nil, ErrInvalidName
	}
	v.mu.RLock()
	rec, ok := v.data.Secrets[name]
	v.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	dek, err := open(v.kek, rec.WrappedDEK, []byte("dek:"+name))
	if err != nil {
		return nil, ErrCorrupt
	}
	defer clear(dek)
	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	pt, err := open(dekAEAD, rec.Ciphertext, []byte("secret:"+name))
	if err != nil {
		return nil, ErrCorrupt
	}
	return pt, nil
}

func (v *Vault) Delete(name string) error {
	if !validName.MatchString(name) {
		return ErrInvalidName
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	rec, ok := v.data.Secrets[name]
	if !ok {
		return ErrNotFound
	}
	delete(v.data.Secrets, name)
	if err := v.persist(); err != nil {
		v.data.Secrets[name] = rec
		return err
	}
	return nil
}

func (v *Vault) List() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	names := make([]string, 0, len(v.data.Secrets))
	for n := range v.data.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Rekey changes the passphrase. Only the DEKs and the audit key are
// re-wrapped; secret ciphertexts are left untouched.
func (v *Vault) Rekey(newPassphrase string) error {
	if newPassphrase == "" {
		return errors.New("vault: empty passphrase")
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	params := kdfParams{Alg: kdfAlg, Iterations: DefaultIterations, Salt: random(saltLen)}
	newKEK, err := deriveKEK(newPassphrase, params)
	if err != nil {
		return err
	}
	next := fileFormat{
		Version:  formatVersion,
		KDF:      params,
		AuditKey: seal(newKEK, v.auditKey, []byte("audit-key")),
		Secrets:  make(map[string]record, len(v.data.Secrets)),
	}
	for name, rec := range v.data.Secrets {
		aad := []byte("dek:" + name)
		dek, err := open(v.kek, rec.WrappedDEK, aad)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrCorrupt, name)
		}
		rec.WrappedDEK = seal(newKEK, dek, aad)
		clear(dek)
		next.Secrets[name] = rec
	}

	old, oldKEK := v.data, v.kek
	v.data, v.kek = next, newKEK
	if err := v.persist(); err != nil {
		v.data, v.kek = old, oldKEK
		return err
	}
	return nil
}

// persist writes the vault atomically (temp file + fsync + rename) so a
// crash never leaves a half-written file. Caller must hold v.mu.
func (v *Vault) persist() error {
	b, err := json.MarshalIndent(v.data, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(v.path, b)
}

func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kagi-vault-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil { // persist the rename itself
		d.Sync()
		d.Close()
	}
	return nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal returns nonce||ciphertext with a fresh random 96-bit nonce.
func seal(a cipher.AEAD, pt, aad []byte) []byte {
	nonce := random(a.NonceSize())
	return a.Seal(nonce, nonce, pt, aad)
}

func open(a cipher.AEAD, blob, aad []byte) ([]byte, error) {
	if len(blob) < a.NonceSize()+a.Overhead() {
		return nil, ErrCorrupt
	}
	n := a.NonceSize()
	return a.Open(nil, blob[:n], blob[n:], aad)
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
