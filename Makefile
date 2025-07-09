.PHONY: all clean install uninstall

PREFIX=/usr/local
GOBUILD=go build
GOGET=go get

all: popub-local popub-relay

clean:
	rm -f popub-local popub-relay

install: all
	install -Dm0755 popub-local "$(DESTDIR)$(PREFIX)/bin/popub-local"
	install -Dm0755 popub-relay "$(DESTDIR)$(PREFIX)/bin/popub-relay"
	$(MAKE) -C systemd install DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)"

uninstall:
	rm -f "$(PREFIX)/bin/popub-local" "$(DESTDIR)$(PREFIX)/bin/popub-relay"
	$(MAKE) -C systemd uninstall DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)"

popub-local: cmd/popub-local/main.go internal/common/common.go internal/delayer/delayer.go
	$(GOGET) -u -v ./cmd/popub-local
	$(GOBUILD) ./cmd/popub-local

popub-relay: cmd/popub-relay/main.go internal/common/common.go internal/delayer/delayer.go
	$(GOGET) -u -v ./cmd/popub-relay
	$(GOBUILD) ./cmd/popub-relay
