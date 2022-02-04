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
        FILELESSLOCK_ID,
};

/*
 * Event Ids should contain only SYSCALLS, Used LSMs
 * other probes that do not change in the kernel
 */

enum bpflock_event_id {
        /*
         * Syscall numbers:
         * https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
         * Since they differ from one arch to another we just go with a small set of syscalls
         * that we are interested in and use same values starting from 10000
         */

        /* Keep names descriptive */

        /* Syscalls start from 10000 */
        SYSCALL_EXECVE_ID               = 1000,
        SYSCALL_EXECVEAT_ID,

        /* BPF */
        SYSCALL_BPF_ID                  = 1100,

        /* LSM IDs start from 20000 */

        /* LSM BPF CONTEXT */
        LSM_BPF_ID                      = 10000,
        LSM_BPF_MAP_ID,

        /* LSM LOCKED_DOWN CONTEXT */
        LSM_LOCKED_DOWN_ID              = 10100,

        LSM_KERNEL_MODULE_REQUEST_ID    = 10200,
        LSM_KERNEL_READ_FILE_ID,
        LSM_KERNEL_LOAD_DATA_ID,

        LSM_BPRM_CREDS_FROM_FILE_ID     = 10300,
};

#define event_id_to_str(id)         #id

#endif /* __BPFLOCK_SHARED_OBJECT_IDS_H */
