# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# Static, reproducible-ish binaries without local paths or debug symbols.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /out/ ./cmd/...

# distroless: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kagid /out/kagictl /out/kagi-ca /usr/local/bin/
USER nonroot:nonroot
WORKDIR /var/lib/kagi
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/kagid"]
CMD ["-tls-cert=/etc/kagi/pki/broker.crt", "-tls-key=/etc/kagi/pki/broker.key", \
     "-client-ca=/etc/kagi/pki/ca.crt", "-policy=/etc/kagi/policy.json", \
     "-vault=/var/lib/kagi/vault.json", "-audit=/var/lib/kagi/audit.log", \
     "-ops-listen=0.0.0.0:9090", "-pq-only"]
