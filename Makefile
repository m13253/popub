.PHONY: all clean install uninstall

all: popub-local popub-relay

PREFIX=/usr/local
GOBUILD=go build

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
	$(GOBUILD) ./cmd/popub-local

popub-relay: cmd/popub-relay/main.go internal/common/common.go internal/delayer/delayer.go
	$(GOBUILD) ./cmd/popub-relay
