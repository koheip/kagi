package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func claims() Claims {
	now := time.Now()
	return Claims{ID: NewID(), Subject: "yata", Grant: "upstream:openai",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), CertThumb: "ab"}
}

func TestMintVerify(t *testing.T) {
	iss := NewIssuer()
	tok, err := iss.Mint(claims())
	if err != nil {
		t.Fatal(err)
	}
	c, err := iss.Verify(tok)
	if err != nil || c.Subject != "yata" {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestForgedClaimsRejected(t *testing.T) {
	iss := NewIssuer()
	tok, _ := iss.Mint(claims())
	parts := strings.Split(tok, ".")
	forged := claims()
	forged.Grant = "upstream:admin-api"
	other, _ := NewIssuer().Mint(forged) // signed by attacker's key
	oparts := strings.Split(other, ".")
	// Splice attacker payload with the genuine signature.
	if _, err := iss.Verify(parts[0] + "." + oparts[1] + "." + parts[2]); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
	if _, err := iss.Verify(other); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign issuer: want ErrSignature, got %v", err)
	}
}

func TestExpired(t *testing.T) {
	iss := NewIssuer()
	c := claims()
	c.ExpiresAt = time.Now().Add(-time.Second).Unix()
	tok, _ := iss.Mint(c)
	if _, err := iss.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestMalformed(t *testing.T) {
	iss := NewIssuer()
	for _, s := range []string{"", "Bearer x", "kagi_v1.", "kagi_v1.a.b", strings.Repeat("A", 5000)} {
		if _, err := iss.Verify(s); err == nil {
			t.Errorf("Verify(%q) accepted", s)
		}
	}
}

// FuzzVerify: no input other than a genuinely minted token may verify,
// and the parser must never panic on attacker-controlled bytes.
func FuzzVerify(f *testing.F) {
	iss := NewIssuer()
	good, _ := iss.Mint(claims())
	f.Add(good)
	f.Add("kagi_v1.e30.AAAA")
	f.Add(strings.Replace(good, "e", "f", 1))
	f.Fuzz(func(t *testing.T, s string) {
		c, err := iss.Verify(s)
		if err == nil && s != good {
			t.Fatalf("forged token accepted: %q -> %+v", s, c)
		}
	})
}

func TestSignatureEncodingNotMalleable(t *testing.T) {
	iss := NewIssuer()
	tok, _ := iss.Mint(claims())
	// 64-byte sig => 86 base64 chars; the last char carries 2 unused bits.
	last := tok[len(tok)-1]
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	idx := strings.IndexByte(alphabet, last)
	for d := 1; d < 4; d++ {
		alt := tok[:len(tok)-1] + string(alphabet[idx^d])
		if _, err := iss.Verify(alt); err == nil {
			t.Fatalf("alternate encoding of the same signature accepted")
		}
	}
}
