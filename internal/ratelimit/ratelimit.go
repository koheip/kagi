// Package ratelimit provides a per-key token bucket limiter with bounded memory.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns a limiter allowing `rate` events/second with bursts up to `burst`.
func New(rate float64, burst int) *Limiter {
	return &Limiter{rate: rate, burst: float64(burst), maxKeys: 10000,
		buckets: map[string]*bucket{}, now: time.Now}
}

// Allow reports whether one event for key may happen now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.evict(now)
			if len(l.buckets) >= l.maxKeys {
				return false // fail closed under key-flooding
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evict drops buckets that have refilled completely (indistinguishable from new).
func (l *Limiter) evict(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
