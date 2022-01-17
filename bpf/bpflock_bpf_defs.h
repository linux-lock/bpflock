// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_BPF_DEFS_H
#define __BPFLOCK_BPF_DEFS_H

#define BPFLOCK_NS_KEY  1

#define TASK_COMM_LEN   16
#define FULL_MAX_ARGS_ARR

#define PROC_DYNAMIC_FIRST 0xF0000000U

#define INVALID_UID     ((uid_t)-1)

struct bl_stat {
        unsigned long  st_dev;	/* Device.  */
        unsigned long  st_ino;	/* File serial number.  */
};

struct sb_elem {
        int freed;
        struct super_block *sb_root;
        struct bpf_spin_lock lock;
};

struct event {
        pid_t   pid;
        pid_t   ppid;
        uid_t   uid;
        char    comm[TASK_COMM_LEN];
};

enum reason {
        reason_allow                    = 1,    /* Allow */
        reason_baseline_allowed,                /* Baseline but allowed with exception */
        reason_baseline,                        /* Baseline */
        reason_baseline_restricted,             /* Baseline but restricted */
        reason_restricted,                      /* Restricted */
};

static __always_inline const char *get_reason_str(const int ret, int reason)
{
	switch (reason) {
	case reason_allow:
		return "allowed (privileged)";
	case reason_baseline_allowed:
		return "allowed (baseline)";
	case reason_baseline:
		return (ret < 0) ? "denied (baseline)" :
			"allowed (baseline)";
	case reason_baseline_restricted:
		return "denied (baseline)";
	case reason_restricted:
		return "denied (restricted)";
	}

	return "";
}

#endif /* __BPFLOCK_BPF_DEFS_H */
