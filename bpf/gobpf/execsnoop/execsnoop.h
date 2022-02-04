/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_EXECSNOOP_H
#define __BPFLOCK_EXECSNOOP_H

#define EXECSNOOP_PROFILE       1
#define EXECSNOOP_TRACE_TARGET  2
#define EXECSNOOP_DEBUG         5

/* The following are how we should trace: key is EXECSNOOP_TRACE_TARGET */
enum execsnoop_trace_by {
        EXECSNOOP_TRACE_BY_FILTER       = 1,
        EXECSNOOP_TRACE_ALL,
};

#endif /* __BPFLOCK_EXECSNOOP_H */
