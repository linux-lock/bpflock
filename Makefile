# SPDX-License-Identifier: Apache-2.0

# Copyright 2021 Djalal Harouni
# Copyright 2017-2020 Authors of Cilium

##@ Default target
all: bpflock  ## Default builds bpflock docker image.
	@echo "Build finished."

# We need this to load in-container related variables
export BASE_IMAGE := $(BASE_IMAGE)

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

defined-%:
	@: $(if $(value $*),,$(error make failed: $* is undefined))

.PHONY: pre-build
pre-build:
	$(info Build started)
	$(info MKDIR build directories)
	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_BINDIR)
	@mkdir -p $(DIST_BPFDIR)
	@mkdir -p $(BUILDLIB)
	@mkdir -p $(DIST_LIBDIR)

clean: clean-bpf-tools clean-images ## Remove bpflock docker images including builder and clean directories.

##@ Inside container targets

# This builds inside container
.PHONY: container-bpf-tools
container-bpf-tools: clean-bpf-tools pre-build | defined-BASE_IMAGE ## Builds bpf tools using libbpf inside container.
	$(info MAKE: start building cbpf tools inside container)
	$(info MAKE -C src all)
	@$(MAKE) -C $(shell pwd)/src all


.PHONY: clean-bpf-tools
clean-bpf-tools: ## Clean bpf-tools build directories.
	@$(RM) -R $(BUILD)
	$(info Clean bpf-tools build directories)

##@ Code checks and tests

.PHONY: govet
govet: ## Run go vet on Go source files of this repository.
	$(GO) vet \
		./pkg/... \
		./test/helpers \
		./test/runtime

.PHONY: gofmt
gofmt: ## Run go fmt on Go source files in the repository.
	for pkg in $(GOFILES); do $(GO) fmt $$pkg; done

.PHONY: test
test: ## Run unit tests
	$(GO) test -v -race $(TESTPACKAGES)

.PHONY: check-code
check-code: gofmt govet test ## Run checks on code

.PHONY: integration
integration: check-code bpflock-integration ## Build bpflock-integration tests docker image and run the tests.
	$(GO) test -failfast -count=1 -v ./test/runtime/...

.PHONY: help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@# There is also a list of target we have to manually put the information about.
	@# These are templated targets.
	$(call print_help_line, "bpflock-builder", "Build bpflock-builder docker image")
	$(call print_help_line, "bpflock", "Build bpflock docker image")
	$(call print_help_line, "bpflock-integration", "Build bpflock-integration tests docker image")
