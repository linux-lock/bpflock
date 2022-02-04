# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Djalal Harouni

.PHONY: all execsnoop
all: execsnoop
	$(info MAKE: finished building Golang bpf packages)

define bpf2go-build
	$(info MAKE: $1 gobpf package)
	cd $1 && $(RM) ./*.o && \
	GOPACKAGE="$1" $(BPF2GO) -cc $(CLANG) -cflags '$(CFLAGS)' bpf $1.bpf.c -- -I../../$(ARCH) $(INCLUDES) -I../../
endef

execsnoop:
	$(call bpf2go-build,$@)

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate
.SECONDARY:
