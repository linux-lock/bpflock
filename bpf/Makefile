# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Djalal Harouni

# Build variables
LIBBPF_UAPI := $(abspath $(LIBBPF)/include/uapi)
LIBBPF_SRC := $(abspath $(LIBBPF)/src)
LIBBPF_OBJ := $(abspath $(BUILDLIB)/libbpf/libbpf.a)

export CLANG ?= clang-$(LLVM_VERSION)
export CFLAGS := -g -O2 -Wall -Werror $(CFLAGS)
export LLVM_STRIP ?= llvm-strip-$(LLVM_VERSION)
export INCLUDES ?= -I$(DIST_LIBDIR) -I$(LIBBPF_UAPI) -I$(BUILD)

UIDGID := $(shell stat -c '%u:%g' ${ROOT_DIR})

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
# MAKEFLAGS += --no-print-directory
endif

TARGETS = \
        bpfrestrict \
        filelesslock \
        kmodlock \
        kimglock
        #

COMMON_OBJ = \
        $(BUILD)/trace_helpers.o \
        $(BUILD)/syscall_helpers.o \
        $(BUILD)/errno_helpers.o \
        $(BUILD)/map_helpers.o \
        $(BUILD)/uprobe_helpers.o \
        $(BUILD)/bpflock_utils.o \
        #

.PHONY: all
all: clean-objects $(LIBBPF_OBJ) gobpf-packages $(TARGETS)
	$(info MAKE: finished building Golang and C bpf programs)

$(BUILDLIB) $(BUILDLIB)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || (echo "Error: libbpf sources are missing - please do: 'git submodule update --init --recursive'" ; false)

# Build libbpf.a
$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(BUILDLIB) $(BUILDLIB)/libbpf
	$(call msg,MAKE LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@) DESTDIR=$(DIST_LIBDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(TARGETS): %: $(BUILD)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(DIST_BPFDIR)
	$(call msg,MAKE BINARY,$(DIST_BPFDIR)/$@)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -o $(DIST_BPFDIR)/$@

$(patsubst %,$(BUILD)/%.o,$(TARGETS)): %.o: %.skel.h

$(BUILD)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(BUILD)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -I$(DIST_LIBDIR) -I$(LIBBPF_UAPI) -I$(BUILD) -c $(filter %.c,$^) -o $@

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o | $(BUILD)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(ARCH)/vmlinux.h | $(BUILD)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(ARCH)/ $(INCLUDES) -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@

gobpf-packages:
	$(info MAKE: start building golang bpf programs)
	@$(MAKE) -C $(shell pwd)/gobpf all

.PHONY: clean
clean:
	@$(RM) -R $(BUILD)

.PHONY: clean-objects
clean-objects:
	@$(RM) -f $(BUILD)/*.o $(BUILD)/*.skel.h

.PHONY: install
install: $(TARGETS)
	$(call msg, INSTALL bpf programs)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIRBPF)
	$(Q)$(INSTALL) $(TARGETS) $(DESTDIR)$(LIBDIRBPF)

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
