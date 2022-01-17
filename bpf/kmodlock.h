/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_KMODLOCK_H
#define __BPFLOCK_KMODLOCK_H

#include "bpflock_security_class.h"
#include "bpflock_bpf_defs.h"

/* kmodlock security class */

#define LOG_KMODLOCK "kmodlock"

#define BPFLOCK_KM_PERM        1
#define BPFLOCK_KM_OP          2

#define BPFLOCK_KM_LOAD         (1 << 0)
#define BPFLOCK_KM_UNLOAD       (1 << 1)
#define BPFLOCK_KM_AUTOLOAD     (1 << 2)
#define BPFLOCK_KM_UNSIGNED     (1 << 3)
#define BPFLOCK_KM_UNSAFEMOD    (1 << 4)

enum dm_env {
        BPFLOCK_KM_NS           = BPFLOCK_NS_KEY,
        BPFLOCK_KM_SB,
};

enum bpflock_dmodules_perm_flag {
        BPFLOCK_KM_ALLOW       = 1,
        BPFLOCK_KM_BASELINE,
        BPFLOCK_KM_RESTRICTED,
};

struct bpflock_class_map dmodules_security_map = {
        "kmodlock",
        "/sys/fs/bpf/bpflock/kmodlock/",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link dmodules_prog_links[] = {
        {
                "kmodlock_autoload",
                "/sys/fs/bpf/bpflock/kmodlock/kmodlock_autoload_link",
        },
        {
                "kmodlock_read_file",
                "/sys/fs/bpf/bpflock/kmodlock/kmodlock_readfile_link",
        },
        {
                "kmodlock_load_data",
                "/sys/fs/bpf/bpflock/kmodlock/kmodlock_loaddata_link",
        },
        {
                "kmodlock_locked_down",
                "/sys/fs/bpf/bpflock/kmodlock/kmodlock_lockedown_link",
        },
};

/* End of kmodlock security class */


#endif /* __BPFLOCK_KMODLOCK_H */