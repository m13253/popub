.PHONY: install uninstall

install:
	install -Dm0644 popub-local@.service /usr/lib/systemd/system/popub-local@.service
	install -Dm0644 popub-relay@.service /usr/lib/systemd/system/popub-relay@.service
	install -Dm0644 example-local.conf /etc/popub/local/example.conf
	install -Dm0644 example-relay.conf /etc/popub/relay/example.conf
	systemctl daemon-reload || true

uninstall:
	rm -f /usr/lib/systemd/system/popub-local@.service /usr/lib/systemd/system/popub-relay@.service
	rm -rf /etc/popub/
	systemctl daemon-reload || true
