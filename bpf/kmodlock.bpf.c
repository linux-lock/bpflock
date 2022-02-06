/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
   To test automatic module loading:
        1. lsmod | grep ipip -
                ipip module is not loaded.
        2. sudo ip tunnel add mytun mode ipip remote 10.0.2.100 local 10.0.2.15 ttl 255
                add tunnel "tunl0" failed: No such device
        3. lsmod | grep ipip -
                ipip module was not loaded.
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

#include "bpflock_defs.bpf.h"
#include "kmodlock.h"

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, uint32_t);
        __type(value, struct process_event);
} kmodlock_event_storage SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 5);
        __type(key, uint32_t);
        __type(value, uint32_t);
} kmodlock_args_map SEC(".maps");

const volatile bool debug = false;

/* readonly test var to enforce profile and avoid bpf maps... */
const volatile enum bpflock_profile global_profile = 0;

static __always_inline bool is_task_allowed(struct process_event *event,
                                            int cgrp_incestor_level)
{
        uint32_t *filter;
        uint32_t k = KMODLOCK_MAPS_FILTER;

        /* By default pass the corresponding filter */
        if (is_pidns_allowed((struct bpf_map *)&bpflock_pidnsmap,
                             BPFLOCK_P_FILTER_PIDNS, event))
                return true;

        if (is_netns_allowed((struct bpf_map *)&bpflock_netnsmap,
                             BPFLOCK_P_FILTER_NETNS, event))
                return true;

        filter = bpf_map_lookup_elem(&kmodlock_args_map, &k);
        /* If fitler then match the cgroupmap */
        if (filter && *filter > 0) {
                if (is_cgroup_allowed((struct bpf_map *)&bpflock_cgroupmap,
                                      *filter, event, cgrp_incestor_level))
                        return true;
        }

        return false;
}

static __always_inline struct super_block *bpf_read_sb_from_file(struct file *file)
{
        struct vfsmount *mnt;

        mnt = BPF_CORE_READ(file, f_path.mnt);
        return BPF_CORE_READ(mnt, mnt_sb);
}

static __always_inline int module_load_check(const char *kmod_name, int eventid, int blocked_op)
{
        uint32_t *val, blocked = 0, reason = 0, ret = 0;
        uint32_t k = KMODLOCK_PROFILE;
        struct process_event *event;
        uint32_t zero = 0;

        val = bpf_map_lookup_elem(&kmodlock_args_map, &k);
        if (!val)
                return 0;

        event = bpf_map_lookup_elem(&kmodlock_event_storage, &zero);
        /* Do not fail as we have to take decisions */
        if (likely(event)) {
                collect_event_info(event, BPF_PROG_TYPE_LSM, BPF_LSM_MAC,
                                   KMODLOCK_ID, eventid);
                collect_event_operation(event, blocked_op);
                if (kmod_name)
                        bpf_probe_read_kernel_str(&event->filename,
                                                  sizeof(event->filename), kmod_name);
        }

        blocked = *val;
        if (blocked == BPFLOCK_P_RESTRICTED)
                return report(event, eventid, -EPERM, reason_restricted, debug);

        if (blocked == BPFLOCK_P_ALLOW) {
                reason = reason_allow;
                ret = 0;
        } else if (blocked == BPFLOCK_P_BASELINE) {
                if (!is_task_allowed(event, 0))
                        return report(event, eventid, -EPERM, reason_baseline, debug);

                reason = reason_baseline;
                ret = 0;
        } else {
                /* Guard */
                return report(event, eventid, -EPERM, reason_restricted, debug);
        }

        k = KMODLOCK_BLOCK_OP;
        val = bpf_map_lookup_elem(&kmodlock_args_map, &k);
        if (!val)
                return report(event, eventid, ret, reason, debug);

        blocked = *val;
        if (blocked & blocked_op)
                return report(event, eventid, -EPERM, reason_baseline_restricted, debug);

        return report(event, eventid, ret, reason, debug);
}

/* TODO: correlate later this event with loading to read module name */
SEC("lsm/locked_down")
int BPF_PROG(km_locked_down, enum lockdown_reason what, int ret)
{
        uint32_t blocked_op = 0;

        if (ret != 0)
                return ret;

        if (what == LOCKDOWN_MODULE_SIGNATURE)
                blocked_op = BPFLOCK_KM_UNSIGNED;
        else if (what == LOCKDOWN_MODULE_PARAMETERS)
                blocked_op = BPFLOCK_KM_UNSAFEMOD;
        else
                /* We are not interested into other events */
                return 0;

        return module_load_check(NULL, LSM_LOCKED_DOWN_ID, blocked_op);
}

SEC("lsm/kernel_module_request")
int BPF_PROG(km_autoload, char *kmod_name, int ret)
{
        if (ret != 0)
                return ret;

        return module_load_check(kmod_name, LSM_KERNEL_MODULE_REQUEST_ID,
                                 BPFLOCK_KM_AUTOLOAD);
}

static int kmod_from_file(struct file *file,
                enum kernel_read_file_id id, bool contents)
{
        int ret;
        const char *p;

        /* If we do not have file context we deny */
        if (!file) {
                /* TODO: even if it is old API it should be logged switch to kprobe */
                return -EPERM;
        }

        p = (char *)BPF_CORE_READ(file, f_path.dentry, d_name.name);
        ret = module_load_check(p, LSM_KERNEL_READ_FILE_ID, BPFLOCK_KM_LOAD);
        if (ret < 0)
                return ret;

        return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(km_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents, int ret)
{
        if (ret != 0)
                return ret;

        return kmod_from_file(file, id, contents);
}

SEC("lsm/kernel_load_data")
int BPF_PROG(km_load_data, enum kernel_read_file_id id,
             bool contents, int ret)
{
        if (ret != 0)
                return ret;

        return kmod_from_file(NULL, (enum kernel_read_file_id) id, contents);
}

static const char _license[] SEC("license") = "GPL";