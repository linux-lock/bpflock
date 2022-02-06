// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/* Shared defs between bpf and userspace programs */

#ifndef __BPFLOCK_SHARED_DEFS_H
#define __BPFLOCK_SHARED_DEFS_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN           16
#endif

#ifndef NAME_MAX
#define NAME_MAX                255
#define PATH_MAX                4096
#endif

#define TASK_FILENAME_LEN       64
#define DATA_LEN                64

#ifndef INVALID_UID
#define INVALID_UID             ((uid_t)-1)
#endif

/* init namespace ids */
enum {
        INIT_PROC_ROOT_INO      = 1,
        INIT_USERNS_ID_INO      = 0xEFFFFFFDU,
        INIT_PIDNS_ID_INO       = 0xEFFFFFFCU, /* PROC_PID_INIT_INO */
        INIT_CGROUPNS_ID_INO    = 0xEFFFFFFBU, /* PROC_CGROUP_INIT_INO */
        INIT_MNTNS_ID_INO       = 0xF0000000U,
        INIT_NETNS_ID_INO       = 0xF0000098U,
};

/* Bpflock profile filters */
#define BPFLOCK_P_FILTER_INVALID        (1 << 0)
/* Filter by namespaces */
#define BPFLOCK_P_FILTER_PIDNS          (1 << 1)
#define BPFLOCK_P_FILTER_MNTNS          (1 << 2)
#define BPFLOCK_P_FILTER_NETNS          (1 << 3)

/* Filter by cgroup v2 */
#define BPFLOCK_P_FILTER_CGROUP         (1 << 4)

enum bpflock_profile {
        BPFLOCK_P_ALLOW       = 1,
        BPFLOCK_P_BASELINE,
        BPFLOCK_P_RESTRICTED,
};

enum reason_value {
        reason_allow                    = 1,    /* Allow */
        reason_baseline_allowed,                /* Baseline but allowed with exception */
        reason_baseline,                        /* Baseline */
        reason_baseline_restricted,             /* Baseline but restricted */
        reason_restricted,                      /* Restricted */
};

struct bpflock_object {
        /* profile in container struct takes precedence */
        int                     object_id;
        enum bpflock_profile    profile;
        int32_t                 priority;
        char                    object_name[TASK_COMM_LEN];
};

#define LOG_BPFLOCK "bpflock"

#define BPFLOCK_PIN_PATH        "/sys/fs/bpf/bpflock/"

#define SHARED_CGROUPMAP        "bpflock_cgroupmap"
#define SHARED_PIDNSMAP         "bpflock_pidnsmap"
#define SHARED_NETNSMAP         "bpflock_netnsmap"
#define SHARED_MNTNSMAP         "bpflock_mntnsmap"
#define SHARED_EVENTS           "bpflock_events"

/* cgroup entry that will reference the per container profile */
struct cgroup_map_entry {
        enum bpflock_profile    profile;
};

struct pidns_map_entry {
        enum bpflock_profile    profile;
};

struct netns_map_entry {
        enum bpflock_profile    profile;
};

struct mntns_map_entry {
        enum bpflock_profile    profile;
};

/* #pragma pack(4) */
struct process_event {
        int             prog_type;
        int             attach_type;

        int             program_id;
        int             event_id;
        int             operation_id;

        pid_t           tgid;
        pid_t           pid;
        pid_t           ppid;
        uid_t           uid;
        gid_t           gid;
        unsigned int    sessionid;

        uint64_t        cgroup_id;
        uint64_t        parent_cgroup_id;

        unsigned int    mntns_id;
        unsigned int    pidns_id;
        uint64_t        netns_id;

        int             reserved1;

        /* Return value of the bpf program for LSM or of the kernel function */
        int             retval;

        /* Map filters that matched the access */
        int             matched_filter;

        /* Reason why access was allowed : enum reason_value */
        int             reason;

        int             reserved2;

        char            comm[TASK_COMM_LEN];
        char            pcomm[TASK_COMM_LEN];
        /* TODO: use full path length and store in map the whole struct */
        char            filename[TASK_FILENAME_LEN];
        char            data[DATA_LEN];
};

#endif /* __BPFLOCK_SHARED_DEFS_H */
