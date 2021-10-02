/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_KIMG_H
#define __BPFLOCK_KIMG_H

#include "bpflock_security_class.h"
#include "bpflock_bpf_defs.h"

/* kernel modules security class */

#define LOG_DISABLE_MODULES "disablemodules"

#define BPFLOCK_DM_PERM        1
#define BPFLOCK_DM_OP          2

#define BPFLOCK_DM_LOAD         (1 << 0)
#define BPFLOCK_DM_UNLOAD       (1 << 1)
#define BPFLOCK_DM_AUTOLOAD     (1 << 2)
#define BPFLOCK_DM_UNSIGNED     (1 << 3)
#define BPFLOCK_DM_UNSAFEMOD    (1 << 4)

enum dm_reason {
        dmreason_allow                  = 1,    /* Allow */
        dmreason_allow_exception,               /* Restrict but allow with exception */
        dmreason_restrict,                      /* Restrict */
        dmreason_deny,                          /* Deny */
};

enum bpflock_disablemodules_perm_flag {
        BPFLOCK_DM_ALLOW       = 1,
        BPFLOCK_DM_RESTRICT,
        BPFLOCK_DM_DENY,
};

struct bpflock_class_map dmodules_security_map = {
        "disable kernel modules",
        "/sys/fs/bpf/bpflock/disable-modules/",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link dmodules_prog_links[] = {
        {
                "bpflock_disable_kernel_modules",
                "/sys/fs/bpf/bpflock/disable-modules/disable_modules_link",
        },
        {
                "bpflock_disable_kernel_modules_readfile",
                "/sys/fs/bpf/bpflock/disable-modules/disable_modules_readfile_link",
        },
        {
                "bpflock_disable_kernel_modules_lockdown",
                "/sys/fs/bpf/bpflock/disable-modules/disable_modules_lockedown_link",
        },
};

/* End of disable modules security class */


#endif /* __BPFLOCK_KIMG_H */