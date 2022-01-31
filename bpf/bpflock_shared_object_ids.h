// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2022 Djalal Harouni
 */

/* Shared defs between bpf and userspace programs */

#ifndef __BPFLOCK_SHARED_OBJECT_IDS_H
#define __BPFLOCK_SHARED_OBJECT_IDS_H

/* This is the bpflock object which the whole program ID */ 
enum bpflock_object_id {
        NONE_ID                      = 0,
        EXECSNOOP_ID,
        BPFRESTRICT_ID,
        KMODLOCK_ID,
        KIMGLOCK_ID,
        FILELESS_ID,
};

#endif /* __BPFLOCK_SHARED_OBJECT_IDS_H */
