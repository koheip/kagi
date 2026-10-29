// Command mock-upstream is a fake OpenAI-compatible API for local demos.
// It checks the injected API key and has a deliberately "leaky" debug
// endpoint that echoes it back, to demonstrate response redaction.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9443", "listen address")
	cert := flag.String("cert", "pki/upstream.crt", "TLS cert")
	key := flag.String("key", "pki/upstream.key", "TLS key")
	want := flag.String("api-key", "sk-demo-1234567890abcdef", "expected API key")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+*want {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}
		var req struct {
			Model    string                           `json:"model"`
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		last := ""
		if n := len(req.Messages); n > 0 {
			last = req.Messages[n-1].Content
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-demo", "object": "chat.completion", "created": time.Now().Unix(), "model": req.Model,
			"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
				"message": map[string]string{"role": "assistant", "content": "（モック応答）受け取った質問: " + last}}},
		})
	})
	mux.HandleFunc("GET /v1/debug/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"authorization":%q}`+"\n", r.Header.Get("Authorization"))
	})
	log.Printf("mock upstream on https://%s", *addr)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
