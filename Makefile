BINARY := power-dns
PKG := ./cmd/power-dns

# Paths used by the install-systemd/uninstall-systemd targets. Override on
# the command line if you want a different layout, e.g.:
#   make install-systemd PREFIX=/opt/power-dns
PREFIX       ?= /usr/local
CONFDIR      ?= /etc/power-dns
STATEDIR     ?= /var/lib/power-dns
SERVICE_USER ?= power-dns
UNIT_DIR     ?= /etc/systemd/system

.PHONY: build run test vet fmt lint docker-up docker-down clean \
        install-systemd uninstall-systemd

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

# install-systemd builds the binary, installs it to $(PREFIX)/bin, creates
# the dedicated $(SERVICE_USER) system user and $(STATEDIR) (for
# records.json/cache.gob), seeds $(CONFDIR)/config.toml from
# config.example.toml if one isn't already there, installs the unit file,
# and reloads systemd. Requires root (run with sudo).
#
# It does NOT enable or start the service -- review $(CONFDIR)/config.toml
# first (at minimum, set `mode` and, in client mode, [relay].url or
# [relay].dot_addr), then:
#   sudo systemctl enable --now power-dns
install-systemd: build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "install-systemd must be run as root, e.g.: sudo make install-systemd"; \
		exit 1; \
	fi
	install -Dm755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)
	getent passwd $(SERVICE_USER) >/dev/null || \
		useradd --system --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER)
	mkdir -p $(CONFDIR)
	[ -f $(CONFDIR)/config.toml ] || install -Dm640 config.example.toml $(CONFDIR)/config.toml
	chown -R $(SERVICE_USER):$(SERVICE_USER) $(CONFDIR)
	mkdir -p $(STATEDIR)
	chown -R $(SERVICE_USER):$(SERVICE_USER) $(STATEDIR)
	install -Dm644 systemd/power-dns.service $(UNIT_DIR)/power-dns.service
	systemctl daemon-reload
	@echo ""
	@echo "Installed. Review $(CONFDIR)/config.toml, then run:"
	@echo "  sudo systemctl enable --now power-dns"

# uninstall-systemd stops and disables the service, removes the unit file
# and installed binary, and reloads systemd. It deliberately leaves
# $(CONFDIR) and $(STATEDIR) (and the $(SERVICE_USER) user) in place, in
# case you're upgrading rather than removing for good -- delete those
# yourself if you want a full clean-up:
#   sudo rm -rf /etc/power-dns /var/lib/power-dns
#   sudo userdel power-dns
uninstall-systemd:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "uninstall-systemd must be run as root, e.g.: sudo make uninstall-systemd"; \
		exit 1; \
	fi
	-systemctl disable --now power-dns
	rm -f $(UNIT_DIR)/power-dns.service
	rm -f $(PREFIX)/bin/$(BINARY)
	systemctl daemon-reload
