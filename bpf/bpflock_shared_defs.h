// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/* Shared defs between bpf and userspace programs */

#ifndef __BPFLOCK_SHARED_DEFS_H
#define __BPFLOCK_SHARED_DEFS_H

enum bpflock_profile {
        BPFLOCK_P_ALLOW       = 1,
        BPFLOCK_P_BASELINE,
        BPFLOCK_P_RESTRICTED,
};

#endif /* __BPFLOCK_SHARED_DEFS_H */
