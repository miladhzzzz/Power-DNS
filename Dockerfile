# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/power-dns ./cmd/power-dns

FROM alpine:3.19 AS runtime

RUN apk add --no-cache ca-certificates && \
    adduser -D -H -u 10001 powerdns

WORKDIR /app
COPY --from=builder /out/power-dns .
COPY config.example.toml ./config.toml

RUN chown -R powerdns:powerdns /app
USER powerdns

EXPOSE 8000
EXPOSE 853
EXPOSE 5335/udp
EXPOSE 5335/tcp

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8000/healthz || exit 1

ENTRYPOINT ["./power-dns"]
CMD ["-config", "config.toml"]
