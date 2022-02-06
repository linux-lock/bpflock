/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2022 Djalal Harouni
 */

#ifndef __BPFLOCK_KMODLOCK_H
#define __BPFLOCK_KMODLOCK_H

#include "bpflock_shared_object_ids.h"
#include "bpflock_security_class.h"

/* kmodlock security class */

#define LOG_KMODLOCK "kmodlock"

/* Arguments */
#define KMODLOCK_PROFILE     1
#define KMODLOCK_ALLOW_OP    2
#define KMODLOCK_BLOCK_OP    3
#define KMODLOCK_MAPS_FILTER 4
#define KMODLOCK_DEBUG       5

#define BPFLOCK_KM_LOAD         (1 << 0)
#define BPFLOCK_KM_UNLOAD       (1 << 1)
#define BPFLOCK_KM_AUTOLOAD     (1 << 2)
#define BPFLOCK_KM_UNSIGNED     (1 << 3)
#define BPFLOCK_KM_UNSAFEMOD    (1 << 4)

struct bpflock_class_map kmodlock_security_map = {
        "kmodlock",
        "/sys/fs/bpf/bpflock/kmodlock/",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link kmodlock_prog_links[] = {
        {
                "kmodlock_autoload",
                "/sys/fs/bpf/bpflock/kmodlock/km_autoload_link",
        },
        {
                "kmodlock_read_file",
                "/sys/fs/bpf/bpflock/kmodlock/km_read_file_link",
        },
        {
                "kmodlock_load_data",
                "/sys/fs/bpf/bpflock/kmodlock/km_load_data_link",
        },
        {
                "kmodlock_locked_down",
                "/sys/fs/bpf/bpflock/kmodlock/km_locked_down_link",
        },
};

/* End of kmodlock security class */
#endif /* __BPFLOCK_KMODLOCK_H */