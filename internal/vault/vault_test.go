package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	// Keep tests fast; production uses DefaultIterations.
	DefaultIterations = 1000
	MinIterations = 1000
}

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.json")
	v, err := Open(p, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return v, p
}

func TestRoundTripAndPersistence(t *testing.T) {
	v, p := newVault(t)
	if err := v.Put("db/password", []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(p, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	got, err := v2.Get("db/password")
	if err != nil || string(got) != "s3cr3t" {
		t.Fatalf("got %q, %v", got, err)
	}
	if names := v2.List(); len(names) != 1 || names[0] != "db/password" {
		t.Fatalf("list = %v", names)
	}
}

func TestPlaintextNeverOnDisk(t *testing.T) {
	v, p := newVault(t)
	v.Put("api-key", []byte("PLAINTEXT-MARKER-12345"))
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("PLAINTEXT-MARKER")) {
		t.Fatal("plaintext leaked to disk")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestWrongPassphrase(t *testing.T) {
	_, p := newVault(t)
	if _, err := Open(p, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestSwappedCiphertextDetected(t *testing.T) {
	v, p := newVault(t)
	v.Put("a", []byte("alpha"))
	v.Put("b", []byte("bravo"))

	var f fileFormat
	raw, _ := os.ReadFile(p)
	json.Unmarshal(raw, &f)
	f.Secrets["a"], f.Secrets["b"] = f.Secrets["b"], f.Secrets["a"]
	raw, _ = json.Marshal(f)
	os.WriteFile(p, raw, 0o600)

	v2, err := Open(p, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Get("a"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swap attack not detected: %v", err)
	}
}

func TestKDFDowngradeRejected(t *testing.T) {
	_, p := newVault(t)
	var f fileFormat
	raw, _ := os.ReadFile(p)
	json.Unmarshal(raw, &f)
	f.KDF.Iterations = 1
	raw, _ = json.Marshal(f)
	os.WriteFile(p, raw, 0o600)
	if _, err := Open(p, "correct horse battery staple"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
}

func TestRekeyKeepsCiphertexts(t *testing.T) {
	v, p := newVault(t)
	v.Put("token", []byte("xyz"))
	before := v.data.Secrets["token"].Ciphertext
	auditBefore := v.AuditKey()

	if err := v.Rekey("new passphrase"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, v.data.Secrets["token"].Ciphertext) {
		t.Fatal("rekey should only re-wrap DEKs")
	}
	if _, err := Open(p, "correct horse battery staple"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal("old passphrase must stop working")
	}
	v2, err := Open(p, "new passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v2.Get("token"); string(got) != "xyz" {
		t.Fatalf("got %q", got)
	}
	if !bytes.Equal(auditBefore, v2.AuditKey()) {
		t.Fatal("audit key must survive rekey so old logs stay verifiable")
	}
}

func TestNameValidation(t *testing.T) {
	v, _ := newVault(t)
	for _, bad := range []string{"", "../etc/passwd", "-flag", "a b", "名前", strings.Repeat("x", 200)} {
		if err := v.Put(bad, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Put(%q) = %v, want ErrInvalidName", bad, err)
		}
	}
}

func TestDeleteAndNotFound(t *testing.T) {
	v, _ := newVault(t)
	v.Put("x", []byte("1"))
	if err := v.Delete("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := v.Delete("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
