BINARY := power-dns
PKG := ./cmd/power-dns

.PHONY: build run test vet fmt lint docker-up docker-down clean

build:
	go build -trimpath -o bin/$(BINARY) $(PKG)

run: build
	./bin/$(BINARY) -config config.toml

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

docker-up:
	docker compose build
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf bin
