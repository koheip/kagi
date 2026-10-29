package ratelimit

import (
	"testing"
	"time"
)

func TestBurstAndRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 3)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("event %d should pass", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th event should be limited")
	}
	if !l.Allow("b") {
		t.Fatal("keys are independent")
	}
	now = now.Add(time.Second)
	if !l.Allow("a") {
		t.Fatal("should refill after 1s")
	}
}

func TestKeyFloodFailsClosed(t *testing.T) {
	l := New(0.001, 1)
	l.maxKeys = 2
	l.Allow("a")
	l.Allow("b")
	if l.Allow("c") {
		t.Fatal("new keys must be refused when table is full of active buckets")
	}
}
