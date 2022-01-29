// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_BPFRESTRICT_H
#define __BPFLOCK_BPFRESTRICT_H

#include "bpflock_shared_object_ids.h"
#include "bpflock_security_class.h"

/* bpf security class */

#define LOG_BPFRESTRICT "bpfrestrict"

/* Bpfrestrict arguments */
#define BPFRESTRICT_PROFILE     1
#define BPFRESTRICT_ALLOW_OP    2
#define BPFRESTRICT_BLOCK_OP    3
#define BPFRESTRICT_MAPS_FILTER 4
#define BPFRESTRICT_DEBUG       5

/* bpfrestrict defined allowed/blocked operations */
#define BPFLOCK_MAP_CREATE      (1 << 0)
#define BPFLOCK_BTF_LOAD        (1 << 1)
#define BPFLOCK_PROG_LOAD       (1 << 2)
#define BPFLOCK_BPF_WRITE       (1 << 8)

struct bpflock_class_map bpf_security_map = {
        "bpf",
        "/sys/fs/bpf/bpflock/bpfrestrict",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link bpf_prog_links[] = {
        {
                "bpflock_bpfrestrict",
                "/sys/fs/bpf/bpflock/bpfrestrict/bpfrestrict_bpf_link",
        },
        {
                "bpflock_bpfrestrict_bpf_write",
                "/sys/fs/bpf/bpflock/bpfrestrict/bpfrestrict_locked_down_link",
        },
};

/* End of bpf security class */
#endif /* __BPFLOCK_BPFRESTRICT_H */
