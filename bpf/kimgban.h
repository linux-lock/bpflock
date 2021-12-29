/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_KIMGBAN_H
#define __BPFLOCK_KIMGBAN_H

#include "bpflock_security_class.h"
#include "bpflock_bpf_defs.h"

/* kimgban security class */

#define LOG_KIMGBAN "kimgban"

#define BPFLOCK_KI_PERM        1
#define BPFLOCK_KI_ALLOW_OP    256

enum ki_reason {
        kireason_allow                  = 1,    /* Allow */
        kireason_allow_exception,               /* Restrict but allow with exception */
        kireason_restrict,                      /* Restrict */
        kireason_deny,                          /* Deny */
};

enum bpflock_bpf_perm_flag {
        BPFLOCK_KI_ALLOW       = 1,
        BPFLOCK_KI_RESTRICT,
        BPFLOCK_KI_DENY,
};

enum lock_kimg_reason {
        LOCK_KIMG_NONE = 0,
        LOCK_KIMG_MODULE_SIGNATURE = 1,
        LOCK_KIMG_DEV_MEM = 2,
        LOCK_KIMG_EFI_TEST = 3,
        LOCK_KIMG_KEXEC = 4,
        LOCK_KIMG_HIBERNATION = 5,
        LOCK_KIMG_PCI_ACCESS = 6,
        LOCK_KIMG_IOPORT = 7,
        LOCK_KIMG_MSR = 8,
        LOCK_KIMG_ACPI_TABLES = 9,
        LOCK_KIMG_PCMCIA_CIS = 10,
        LOCK_KIMG_TIOCSSERIAL = 11,
        LOCK_KIMG_MODULE_PARAMETERS = 12,
        LOCK_KIMG_MMIOTRACE = 13,
        LOCK_KIMG_DEBUGFS = 14,
        LOCK_KIMG_XMON_WR = 15,
        LOCK_KIMG_BPF_WRITE_USER = 16,
        LOCK_KIMG_INTEGRITY_MAX = 17,
        /*
          We support only to BPF_WRITE_USER for backward compatibility,
          LOCKDOWN_KCORE protects kcore which is read-only anyway.
        */

        LOCK_KIMG_BTF_LOAD = 512,
};

struct bpflock_class_map kimg_security_map = {
        "kernel image ban",
        "/sys/fs/bpf/bpflock/kimgban",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link bpf_prog_links[] = {
        {
                "bpflock_kimgban_lock",
                "/sys/fs/bpf/bpflock/kimgban/kimgban_lockdown_link",
        },
        {
                "bpflock_kimgban_bpf",
                "/sys/fs/bpf/bpflock/kimgban/kimgban_bpf_link",
        }
};

/* End of kimgban security class */


#endif /* __BPFLOCK_KIMGBAN_H */