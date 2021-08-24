.PHONY: install uninstall

PREFIX = /usr/local
SYSTEMD_DIR = /usr/lib/systemd
SYSTEMD_UNIT_DIR = $(SYSTEMD_DIR)/system

install:
	sed "s|@PREFIX@|$(PREFIX)|" popub-local@.service.in > popub-local@.service
	sed "s|@PREFIX@|$(PREFIX)|" popub-relay@.service.in > popub-relay@.service
	install -Dm0644 popub-local@.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/popub-local@.service"
	install -Dm0644 popub-relay@.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/popub-relay@.service"

	install -Dm0644 example-local.conf "$(DESTDIR)/etc/popub/local/example.conf"
	install -Dm0644 example-relay.conf "$(DESTDIR)/etc/popub/relay/example.conf"
	systemctl daemon-reload || true

uninstall:
	rm -f "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"/popub-{local,relay}@.service
	rm -rf "$(DESTDIR)/etc/popub/"
	systemctl daemon-reload || true
