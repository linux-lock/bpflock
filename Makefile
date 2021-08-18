# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

.PHONY: all clean
all:
	$(MAKE) -C ./src all

clean:
	$(call msg,CLEAN)
	$(MAKE) -C ./src clean

install: $(APPS)
	$(call msg, INSTALL libbpf-tools)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/bin
	$(Q)$(INSTALL) $(APPS) $(DESTDIR)$(prefix)/bin
	$(Q)cp -a $(APP_ALIASES) $(DESTDIR)$(prefix)/bin
