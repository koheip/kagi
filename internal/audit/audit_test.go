package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var key = []byte("0123456789abcdef0123456789abcdef")

func writeLog(t *testing.T, n int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append("alice", "get", "db/password", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	return p
}

func TestChainVerifiesAndResumes(t *testing.T) {
	p := writeLog(t, 3)
	l, err := Open(p, key) // resume
	if err != nil {
		t.Fatal(err)
	}
	l.Append("bob", "put", "x", "ok")
	l.Close()
	f, _ := os.Open(p)
	defer f.Close()
	if n, err := Verify(f, key); err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func mutate(t *testing.T, p string, fn func(lines []string) []string) {
	t.Helper()
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	os.WriteFile(p, []byte(strings.Join(fn(lines), "\n")+"\n"), 0o600)
}

func TestTamperDetection(t *testing.T) {
	cases := map[string]func([]string) []string{
		"edit field": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"result":"ok"`, `"result":"denied"`, 1)
			return l
		},
		"delete middle": func(l []string) []string { return append(l[:1], l[2:]...) },
		"reorder":       func(l []string) []string { l[0], l[1] = l[1], l[0]; return l },
		"inject field": func(l []string) []string {
			l[0] = strings.Replace(l[0], `{`, `{"x":1,`, 1)
			return l
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeLog(t, 3)
			mutate(t, p, fn)
			if _, err := Open(p, key); !errors.Is(err, ErrTampered) {
				t.Fatalf("want ErrTampered, got %v", err)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	p := writeLog(t, 1)
	raw, _ := os.ReadFile(p)
	if _, err := Verify(bytes.NewReader(raw), []byte("other key")); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestNoLogInjection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	l, _ := Open(p, key)
	l.Append("eve\n{\"seq\":99}", "get", "x", "ok")
	l.Close()
	raw, _ := os.ReadFile(p)
	if bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatal("newline in field produced an extra log line")
	}
}
