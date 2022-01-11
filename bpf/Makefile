# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Djalal Harouni

# Build variables
LIBBPF_UAPI := $(abspath $(LIBBPF)/include/uapi)
LIBBPF_SRC := $(abspath $(LIBBPF)/src)
LIBBPF_OBJ := $(abspath $(BUILDLIB)/libbpf/libbpf.a)

CLANG ?= clang-$(LLVM_VERSION)
CFLAGS := -g -O2 -Wall -Werror $(CFLAGS)
LLVM_STRIP ?= llvm-strip-$(LLVM_VERSION)
INCLUDES := -I$(DIST_LIBDIR) -I$(LIBBPF_UAPI) -I$(BUILD)

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
        kimglock \
        bpfrestrict \
        kmodlock \
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
all: $(LIBBPF_OBJ) $(TARGETS)
	$(info MAKE: finished building cbpf tools)

$(BUILDLIB) $(BUILDLIB)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || (echo "Error: libbpf sources are missing - please do: 'git submodule update --init'" ; false)

# Build libbpf.a
$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(BUILDLIB) $(BUILDLIB)/libbpf
	$(call msg,MAKE LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@) DESTDIR=$(DIST_LIBDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BUILD)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(BUILD)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -I$(DIST_LIBDIR) -I$(LIBBPF_UAPI) -I$(BUILD) -c $(filter %.c,$^) -o $@

$(TARGETS): %: $(BUILD)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(DIST_BPFDIR)
	$(call msg,MAKE BINARY,$(DIST_BPFDIR)/$@)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -o $(DIST_BPFDIR)/$@

$(patsubst %,$(BUILD)/%.o,$(TARGETS)): %.o: %.skel.h

$(BUILD)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(ARCH)/vmlinux.h | $(BUILD)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(ARCH)/ $(INCLUDES) -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o | $(BUILD)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

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
