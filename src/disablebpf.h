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

enum bpflock_bpf_perm_flag {
        BPFLOCK_BPF_ALLOW       = 1,
        BPFLOCK_BPF_RESTRICT,
        BPFLOCK_BPF_DENY,
};

enum bpflock_bpf_op {
        BPFLOCK_MAP_CREATE      = (1 << 0),
        BPFLOCK_BTF_LOAD        = (1 << 1),
        BPFLOCK_PROG_LOAD       = (1 << 2),
};

struct bpflock_class_map bpf_security_map = {
        "bpf",
        "/sys/fs/bpf/bpflock/disable-bpf",
        { NULL },
        { BPFLOCK_BPF_PERM, BPFLOCK_BPF_OP, BPFLOCK_MAP_CREATE, BPFLOCK_BTF_LOAD, BPFLOCK_PROG_LOAD, 0 }
};

/* End of bpf security class */


#endif /* __BPFLOCK_DISABLEBPF_H */