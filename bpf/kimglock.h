/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_KIMGLOCK_H
#define __BPFLOCK_KIMGLOCK_H

#include "bpflock_security_class.h"
#include "bpflock_bpf_defs.h"

/* kimglock security class */

#define LOG_KIMGLOCK "kimglock"

#define BPFLOCK_KI_PERM        1
#define BPFLOCK_KI_ALLOW_OP    256

enum bpflock_bpf_perm_flag {
        BPFLOCK_KI_ALLOW       = 1,
        BPFLOCK_KI_BASELINE,
        BPFLOCK_KI_RESTRICTED,
};

#define FOREACH_KIMGREASON(KIMGREASON) \
        KIMGREASON(LOCK_KIMG_NONE)      \
        KIMGREASON(LOCK_KIMG_MODULE_SIGNATURE)  \
        KIMGREASON(LOCK_KIMG_DEV_MEM)   \
        KIMGREASON(LOCK_KIMG_EFI_TEST)   \
        KIMGREASON(LOCK_KIMG_KEXEC)   \
        KIMGREASON(LOCK_KIMG_HIBERNATION)   \
        KIMGREASON(LOCK_KIMG_PCI_ACCESS)   \
        KIMGREASON(LOCK_KIMG_IOPORT)   \
        KIMGREASON(LOCK_KIMG_MSR)   \
        KIMGREASON(LOCK_KIMG_ACPI_TABLES)   \
        KIMGREASON(LOCK_KIMG_PCMCIA_CIS)   \
        KIMGREASON(LOCK_KIMG_TIOCSSERIAL)   \
        KIMGREASON(LOCK_KIMG_MODULE_PARAMETERS)   \
        KIMGREASON(LOCK_KIMG_MMIOTRACE)   \
        KIMGREASON(LOCK_KIMG_DEBUGFS)   \
        KIMGREASON(LOCK_KIMG_XMON_WR)   \
        KIMGREASON(LOCK_KIMG_BPF_WRITE_USER)   \
        KIMGREASON(LOCK_KIMG_INTEGRITY_MAX)   \
        KIMGREASON(LOCK_KIMG_KCORE)   \
        KIMGREASON(LOCK_KIMG_KPROBES)   \
        KIMGREASON(LOCK_KIMG_BPF_READ_KERNEL)   \
        KIMGREASON(LOCK_KIMG_PERF)   \
        KIMGREASON(LOCK_KIMG_TRACEFS)   \
        KIMGREASON(LOCK_KIMG_XMON_RW)   \
        KIMGREASON(LOCK_KIMG_XFRM_SECRET)   \
        KIMGREASON(LOCK_KIMG_CONFIDENTIALITY_MAX)   \

#define GENERATE_ENUM(ENUM) ENUM,

enum kimg_enum {
        FOREACH_KIMGREASON(GENERATE_ENUM)
};

enum extra_kimg_enum {
        /*
          We support only to BPF_WRITE_USER for backward compatibility,
          LOCK_KIMG_KCORE protects kcore which is read-only anyway.
        */

        LOCK_KIMG_BTF_LOAD = 512,
};

struct bpflock_class_map kimg_security_map = {
        "kernel image lockdown",
        "/sys/fs/bpf/bpflock/kimglock",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link bpf_prog_links[] = {
        {
                "bpflock_kimglock_lock",
                "/sys/fs/bpf/bpflock/kimglock/kimglock_lockdown_link",
        },
        {
                "bpflock_kimglock_bpf",
                "/sys/fs/bpf/bpflock/kimglock/kimglock_bpf_link",
        }
};

/* End of kimglock security class */
#endif /* __BPFLOCK_KIMGLOCK_H */