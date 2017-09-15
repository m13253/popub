.PHONY: all clean install uninstall

all: popub-local/popub-local popub-relay/popub-relay

PREFIX=/usr/local

clean:
	rm -f popub-local/popub-local popub-relay/popub-relay

install: all
	install -Dm0755 popub-local/popub-local popub-relay/popub-relay "$(PREFIX)/bin/"
	$(MAKE) -C systemd install

uninstall:
	rm -f "$(PREFIX)/bin/popub-local" "$(PREFIX)/bin/popub-relay"
	$(MAKE) -C systemd uninstall

popub-local/popub-local: popub-local/main.go popub-local/delayer.go
	cd popub-local && go build

popub-relay/popub-relay: popub-local/main.go popub-local/delayer.go
	cd popub-relay && go build


