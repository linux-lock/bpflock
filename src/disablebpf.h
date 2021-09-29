/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_DISABLEBPF_H
#define __BPFLOCK_DISABLEBPF_H

#include "bpflock_security_class.h"

/* bpf security class */

#define BPFLOCK_BPF_PERM        1
#define BPFLOCK_BPF_OP          2

#define BPFLOCK_MAP_CREATE      (1 << 0)
#define BPFLOCK_BTF_LOAD        (1 << 1)
#define BPFLOCK_PROG_LOAD       (1 << 2)
#define BPFLOCK_BPF_WRITE       (1 << 8)

#define DISABLEBPF_NS_MAP_PIN      "/sys/fs/bpf/bpflock/disablebpf_ns_map"

enum bpflock_bpf_perm_flag {
        BPFLOCK_BPF_ALLOW       = 1,
        BPFLOCK_BPF_RESTRICT,
        BPFLOCK_BPF_DENY,
};

struct bpflock_class_map bpf_security_map = {
        "bpf",
        "/sys/fs/bpf/bpflock/disable-bpf",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link bpf_prog_links[] = {
        {
                "bpflock_disablebpf",
                "/sys/fs/bpf/bpflock/disable-bpf/disablebpf_link",
        },
        {
                "bpflock_disablebpf_bpf_write",
                "/sys/fs/bpf/bpflock/disable-bpf/disablebpf_bpf_write_link",
        },
};

/* End of bpf security class */


#endif /* __BPFLOCK_DISABLEBPF_H */
