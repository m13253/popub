.PHONY: install uninstall

PREFIX = /usr/local
LAUNCHD_DIR = /Library
LAUNCHD_DAEMON_DIR = $(LAUNCHD_DIR)/LaunchDaemons

install:
	sed "s|@PREFIX@|$(PREFIX)|" moe.biscuit.popub-local.plist.in > moe.biscuit.popub-local.plist
	sed "s|@PREFIX@|$(PREFIX)|" moe.biscuit.popub-relay.plist.in > moe.biscuit.popub-relay.plist
	install -m0644 moe.biscuit.popub-local.plist "$(DESTDIR)$(LAUNCHD_DAEMON_DIR)/moe.biscuit.popub-local.plist"
	install -m0644 moe.biscuit.popub-relay.plist "$(DESTDIR)$(LAUNCHD_DAEMON_DIR)/moe.biscuit.popub-relay.plist"

uninstall:
	rm -f "$(DESTDIR)$(LAUNCHD_DAEMON_DIR)"/moe.biscuit.popub-{local,relay}.plist
