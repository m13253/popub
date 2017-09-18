.PHONY: install uninstall

PREFIX = /usr/local
SYSTEMD_DIR = /usr/lib/systemd
SYSTEMD_UNIT_DIR = $(SYSTEMD_DIR)/system
SYSTEMD_USER_DIR = $(SYSTEMD_DIR)/user

install:
	sed "s|<PREFIX>|$(PREFIX)|; s|<USER>|nobody|" popub-local@.service.in > popub-local@.service
	sed "s|<PREFIX>|$(PREFIX)|; s|<USER>|nobody|" popub-relay@.service.in > popub-relay@.service
	install -Dm0644 popub-local@.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/popub-local@.service"
	install -Dm0644 popub-relay@.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/popub-relay@.service"

	sed "s|<PREFIX>|$(PREFIX)|; s|<USER>|%u|; /CAP_NET/d" popub-local@.service.in > popub-local@.service
	sed "s|<PREFIX>|$(PREFIX)|; s|<USER>|%u|; /CAP_NET/d" popub-relay@.service.in > popub-relay@.service
	install -Dm0644 popub-local@.service "$(DESTDIR)$(SYSTEMD_USER_DIR)/popub-local@.service"
	install -Dm0644 popub-relay@.service "$(DESTDIR)$(SYSTEMD_USER_DIR)/popub-relay@.service"

	install -Dm0644 example-local.conf "$(DESTDIR)/etc/popub/local.d/example"
	install -Dm0644 example-relay.conf "$(DESTDIR)/etc/popub/relay.d/example"
	systemctl daemon-reload || true

uninstall:
	rm -f "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"/popub-{local,relay}@.service
	rm -f "$(DESTDIR)$(SYSTEMD_USER_DIR)"/popub-{local,relay}@.service
	rm -rf "$(DESTDIR)/etc/popub/"
	systemctl daemon-reload || true
