# Distroless multi-stage production image for Prometheus Envoy ext_proc / MCP Sidecar
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/prometheus-sidecar ./cmd/prometheus-sidecar

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/prometheus-sidecar /usr/local/bin/prometheus-sidecar
EXPOSE 8080 50051
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/prometheus-sidecar"]
CMD ["--addr", "0.0.0.0:8080", "--grpc-addr", "0.0.0.0:50051"]
