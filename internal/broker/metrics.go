package broker

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

// metrics is a tiny Prometheus text-format exporter (no dependencies).
type metrics struct {
	mu sync.Mutex
	c  map[string]int64
}

func newMetrics() *metrics { return &metrics{c: map[string]int64{}} }

func (m *metrics) inc(name string) {
	m.mu.Lock()
	m.c[name]++
	m.mu.Unlock()
}

func (m *metrics) get(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.c[name]
}

// OpsHandler serves /metrics and /healthz. Bind it to localhost or an
// internal network only; it is intentionally unauthenticated.
func (b *Broker) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		b.metrics.mu.Lock()
		names := make([]string, 0, len(b.metrics.c))
		for k := range b.metrics.c {
			names = append(names, k)
		}
		sort.Strings(names)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, n := range names {
			fmt.Fprintf(w, "kagi_%s %d\n", n, b.metrics.c[n])
		}
		b.metrics.mu.Unlock()
	})
	return mux
}
