// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Djalal Harouni
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

#include "bpflock_defs.bpf.h"
#include "filelesslock.h"

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, uint32_t);
        __type(value, struct process_event);
} filelesslock_event_storage SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 5);
        __type(key, uint32_t);
        __type(value, uint32_t);
} filelesslock_args_map SEC(".maps");

const volatile bool debug = false;

/* readonly test var to enforce profile and avoid bpf maps... */
const volatile enum bpflock_profile global_profile = 0;

static __always_inline bool is_task_allowed(struct process_event *event,
                                            int cgrp_incestor_level)
{
        uint32_t *filter;
        uint32_t k = FILELESSLOCK_MAPS_FILTER;

        /* By default pass the corresponding filter */
        if (is_pidns_allowed((struct bpf_map *)&bpflock_pidnsmap,
                             BPFLOCK_P_FILTER_PIDNS, event))
                return true;

        if (is_netns_allowed((struct bpf_map *)&bpflock_netnsmap,
                             BPFLOCK_P_FILTER_NETNS, event))
                return true;

        filter = bpf_map_lookup_elem(&filelesslock_args_map, &k);
        /* If fitler then match the cgroupmap */
        if (filter && *filter > 0) {
                if (is_cgroup_allowed((struct bpf_map *)&bpflock_cgroupmap,
                                      *filter, event, cgrp_incestor_level))
                        return true;
        }

        return false;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file, int ret)
{
        uint32_t *val, blocked = 0, reason = 0, zero = 0;
        uint32_t k = FILELESSLOCK_PROFILE;
        unsigned int links;
        struct process_event *event;
        struct task_struct *task;
        struct file *f;
        const unsigned char *p;

        if (ret != 0 )
                return ret;

        val = bpf_map_lookup_elem(&filelesslock_args_map, &k);
        if (!val)
                return ret;

        links = BPF_CORE_READ(file, f_path.dentry, d_inode, __i_nlink);
        if (links > 0)
                return ret;

        event = bpf_map_lookup_elem(&filelesslock_event_storage, &zero);
        /* Do not fail as we have to take decisions */
        if (event) {
                collect_event_info(event, BPF_PROG_TYPE_LSM, BPF_LSM_MAC,
                                   FILELESSLOCK_ID, LSM_BPRM_CREDS_FROM_FILE_ID);
                p = BPF_CORE_READ(file, f_path.dentry, d_name.name);
                bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), p);
                /*
                fdpath needs a newer vmlinux.h https://patchwork.kernel.org/project/linux-security-module/patch/87k0z66x8f.fsf@x220.int.ebiederm.org/
                */
        }

        /* Check the global profile */
        blocked = *val;
        if (blocked == BPFLOCK_P_RESTRICTED)
                return report(event, LSM_BPRM_CREDS_FROM_FILE_ID, -EPERM,
                              reason_restricted, debug);

        if (blocked == BPFLOCK_P_ALLOW)
                return report(event, LSM_BPRM_CREDS_FROM_FILE_ID, 0,
                              reason_allow, debug);

        reason = reason_baseline;
        if (!is_task_allowed(event, 0))
                ret = -EPERM;

        return report(event, LSM_BPRM_CREDS_FROM_FILE_ID, ret,
                      reason_baseline, debug);

}

static const char _license[] SEC("license") = "GPL";
