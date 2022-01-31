// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2022 Djalal Harouni
 */

/* Shared defs between bpf and userspace programs */

#ifndef __BPFLOCK_SHARED_OBJECT_IDS_H
#define __BPFLOCK_SHARED_OBJECT_IDS_H

/* This is the bpflock object which the whole program ID */ 
enum bpflock_object_id {
        EXECSNOOP_ID                    = 1,
        BPFRESTRICT_ID,
        KMODLOCK_ID,
        KIMGLOCK_ID,
        FILELESS_ID,
};

enum bpflock_event_id {
        /*
         * Syscall numbers:
         * https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
         * Since they differ from one arch to another we just go with a small set of syscalls
         * that we are interested in and use same values starting from 10000
         */

        /* Keep names descriptive */

        /* Syscalls start from 10000 */
        SYSCALL_EXECVE_ID               = 10000,
        SYSCALL_EXECVEAT_ID,
        SYSCALL_BPF_ID,

        /* LSM IDs start from 20000 */

        /* LSM BPF CONTEXT */
        LSM_BPF_ID                      = 20000,
        LSM_BPF_MAP_ID,

        /* LSM LOCKED_DOWN CONTEXT */
        LSM_LOCKED_DOWN_ID              = 20100,
};

#define event_id_to_str(id)         #id

#endif /* __BPFLOCK_SHARED_OBJECT_IDS_H */
