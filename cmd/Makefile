# SPDX-License-Identifier: Apache-2.0

# Copyright 2022 Djalal Harouni
# Copyright 2017-2020 Authors of Cilium

ifndef GO_BUILD
include ../Makefile.defs
endif

TARGET := bpflock

.PHONY: all $(TARGET)
all: $(TARGET)

$(TARGET): ../Makefile ../Makefile.defs Makefile
	$(GO_BUILD) -o $(DIST_BINDIR)/$@ ./$@

clean:
	@rm -f $(DIST_BINDIDR)/$(TARGET)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	$(QUIET)$(INSTALL) -m 0755 $(DIST_BINDIR)/$(TARGET) $(DESTDIR)$(LIBDIR)
