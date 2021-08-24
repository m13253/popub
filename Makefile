.PHONY: all clean install uninstall

all: popub-local popub-relay

PREFIX=/usr/local
GOBUILD=go build

clean:
	rm -f popub-local/popub-local popub-relay/popub-relay

install: all
	install -Dm0755 popub-local "$(DESTDIR)$(PREFIX)/bin/popub-local"
	install -Dm0755 popub-relay "$(DESTDIR)$(PREFIX)/bin/popub-relay"
	$(MAKE) -C contrib/systemd install DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)"

uninstall:
	rm -f "$(PREFIX)/bin/popub-local" "$(DESTDIR)$(PREFIX)/bin/popub-relay"
	$(MAKE) -C contrib/systemd uninstall DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)"

popub-local:
	$(GOBUILD) github.com/m13253/popub/cmd/popub-local

popub-relay:
	$(GOBUILD) github.com/m13253/popub/cmd/popub-relay

