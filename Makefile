.PHONY: build test fuzz vuln demo docker clean

build:
	CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...

test:
	go vet ./...
	go test -race -cover ./...

fuzz:
	go test ./internal/token -run '^$$' -fuzz FuzzVerify -fuzztime 60s

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

demo:
	./scripts/demo.sh

docker:
	docker build -t kagi:local .

clean:
	rm -rf bin
