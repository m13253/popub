.PHONY: all clean install uninstall

all: popub-local/popub-local popub-relay/popub-relay

PREFIX=/usr/local
GOBUILD=go build

clean:
	rm -f popub-local/popub-local popub-relay/popub-relay

install: all
	install -Dm0755 popub-local/popub-local "$(DESTDIR)$(PREFIX)/bin/popub-local"
	install -Dm0755 popub-relay/popub-relay "$(DESTDIR)$(PREFIX)/bin/popub-relay"
	$(MAKE) -C systemd install DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)"

uninstall:
	rm -f "$(PREFIX)/bin/popub-local" "$(DESTDIR)$(PREFIX)/bin/popub-relay"
	$(MAKE) -C systemd uninstall DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)"

popub-local/popub-local: popub-local/main.go popub-local/delayer.go
	cd popub-local && $(GOBUILD)

popub-relay/popub-relay: popub-local/main.go popub-local/delayer.go
	cd popub-relay && $(GOBUILD)


