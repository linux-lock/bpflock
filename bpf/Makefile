# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
BUILD ?= $(abspath ../build/)
BUILDLIBS ?= $(abspath ../build/libs/)
BPFTOOL ?= $(abspath ../tools/bpftool)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath ./cc/libbpf/src)
LIBBPF_OBJ := $(abspath $(BUILDLIBS)/libbpf.a)
INCLUDES := -I$(BUILDLIBS) -I./cc/libbpf/include/uapi
CFLAGS := -g -O2 -Wall
INSTALL ?= install
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

ifeq ($(wildcard $(ARCH)/),)
$(error Architecture $(ARCH) is not supported yet. Please open an issue)
endif

APPS = \
        kimg \
        disablemoduleautoload \
        disablebpf \
        disablemodules \
        restrictfilesystems \
	#

COMMON_OBJ = \
	$(BUILDLIBS)/trace_helpers.o \
	$(BUILDLIBS)/syscall_helpers.o \
	$(BUILDLIBS)/errno_helpers.o \
	$(BUILDLIBS)/map_helpers.o \
	$(BUILDLIBS)/uprobe_helpers.o \
	$(BUILDLIBS)/bpflock_utils.o \
	#

.PHONY: all
all: $(APPS)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(BUILD) $(APPS)

$(BUILDLIBS) $(BUILDLIBS)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(APPS): %: $(BUILDLIBS)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(BUILDLIBS)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -o ${BUILD}/$@

$(patsubst %,$(BUILDLIBS)/%.o,$(APPS)): %.o: %.skel.h

$(BUILDLIBS)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(BUILDLIBS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(BUILDLIBS)/%.skel.h: $(BUILDLIBS)/%.bpf.o | $(BUILDLIBS)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(BUILDLIBS)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(ARCH)/vmlinux.h | $(BUILDLIBS)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     -I$(ARCH)/ $(INCLUDES) -c $(filter %.c,$^) -o $@ &&      \
	$(LLVM_STRIP) -g $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(BUILDLIBS)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install
install: $(APPS)
	$(call msg, INSTALL libbpf-tools)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/bin
	$(Q)$(INSTALL) $(APPS) $(DESTDIR)$(prefix)/bin
	$(Q)cp -a $(APP_ALIASES) $(DESTDIR)$(prefix)/bin

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
