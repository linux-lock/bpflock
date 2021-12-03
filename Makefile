# SPDX-License-Identifier: Apache-2.0

# Copyright 2021 Djalal Harouni
# Copyright 2017-2020 Authors of Cilium

all: clean bpflock  ## Default builds bpflock docker image.
	@echo "Build finished."

include Makefile.defs

ifndef BASE_IMAGE
-include Makefile.docker
endif


define print_help_line
    @printf "  \033[36m%-29s\033[0m %s.\n" $(1) $(2)
endef

# Targets to build
kubectl_bpflock ?= $(BUILDBINS)/kubectl-bpflock

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

.PHONY: clean
clean:
	$(info CLEAN build)
	@$(RM) -R $(BUILD)

.PHONY: help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@# There is also a list of target we have to manually put the information about.
	@# These are templated targets.
	$(call print_help_line,"bpflock-builder","Build bpflock-builder docker image")
	$(call print_help_line,"bpflock","Build bpflock docker image")


# This builds inside container
.PHONY: bpf-tools
bpf-tools: clean pre-build
	$(info MAKE: start building cbpf tools)
	$(info MAKE -C src all)
	@$(MAKE) -C $(shell pwd)/src all