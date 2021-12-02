# SPDX-License-Identifier: Apache-2.0

# Copyright 2021 Djalal Harouni

all: build-containers
	@echo "Build finished."

include Makefile.defs

ifndef BASE_IMAGE
-include Makefile.docker
endif

# Targets to build
kubectl_bpflock ?= $(BUILDBINS)/kubectl-bpflock

.PHONY: build-containers
build-containers: clean bpflock-builder bpflock-builder-tag

${kubectl_bpflock}:
	CGO_ENABLED=1 $(GO) build ${LDFLAGS} -o $@ ./cmd/kubectl-bpflock

.PHONY: pre-build
pre-build:
	$(info Build started)
	$(info MKDIR build directories)
	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_BINDIR)
	@mkdir -p $(BUILDLIB)
	@mkdir -p $(DIST_LIBDIR)

.PHONY: bpf-tools
bpf-tools: clean pre-build
	$(info MAKE: start building cbpf tools)
	$(info MAKE -C src all)
	@$(MAKE) -C $(shell pwd)/src all

.PHONY: clean
clean:
	$(info CLEAN build)
	@$(RM) -R $(BUILD)