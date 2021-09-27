/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_KIMG_H
#define __BPFLOCK_KIMG_H

#include "bpflock_security_class.h"
#include "bpflock_bpf_defs.h"

/* kimg security class */

#define BPFLOCK_KI_PERM        1
#define BPFLOCK_KI_ALLOW_OP    256

#define KIMG_NS_MAP_PIN      "/sys/fs/bpf/bpflock/kimg_ns_map"

enum bpflock_bpf_perm_flag {
        BPFLOCK_KI_ALLOW       = 1,
        BPFLOCK_KI_RESTRICT,
        BPFLOCK_KI_DENY,
};

struct bpflock_class_map kimg_security_map = {
        "bpf",
        "/sys/fs/bpf/bpflock/kimg",
        { NULL },
        { 0 }
};

/* End of kimg security class */


#endif /* __BPFLOCK_KIMG_H */