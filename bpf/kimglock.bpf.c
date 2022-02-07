/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2022 Djalal Harouni
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

#include "bpflock_defs.bpf.h"
#include "kimglock.h"

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, uint32_t);
        __type(value, struct process_event);
} kimglock_event_storage SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 5);
        __type(key, uint32_t);
        __type(value, uint32_t);
} kimglock_args_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 30);
        __type(key, uint32_t);
        __type(value, uint32_t);
} kimglock_block_map SEC(".maps");

const volatile bool debug = false;

/* readonly test var to enforce profile and avoid bpf maps... */
const volatile enum bpflock_profile global_profile = 0;

static __always_inline bool is_task_allowed(struct process_event *event,
                                            int cgrp_incestor_level)
{
        uint32_t *filter;
        uint32_t k = KIMGLOCK_MAPS_FILTER;

        /* By default pass the corresponding filter */
        if (is_pidns_allowed((struct bpf_map *)&bpflock_pidnsmap,
                             BPFLOCK_P_FILTER_PIDNS, event))
                return true;

        if (is_netns_allowed((struct bpf_map *)&bpflock_netnsmap,
                             BPFLOCK_P_FILTER_NETNS, event))
                return true;

        filter = bpf_map_lookup_elem(&kimglock_args_map, &k);
        /* If fitler then match the cgroupmap */
        if (filter && *filter > 0) {
                if (is_cgroup_allowed((struct bpf_map *)&bpflock_cgroupmap,
                                      *filter, event, cgrp_incestor_level))
                        return true;
        }

        return false;
}

int check_kimg_perm(int what)
{
        uint32_t *val, blocked = 0, reason = 0;
        struct process_event *event;
        uint32_t k = KIMGLOCK_PROFILE;
        uint32_t zero = 0;
        const char *op;
        int ret = 0;

        val = bpf_map_lookup_elem(&kimglock_args_map, &k);
        if (!val)
                return ret;

        event = bpf_map_lookup_elem(&kimglock_event_storage, &zero);
        /* Do not fail as we have to take decisions */
        if (event) {
                collect_event_info(event, BPF_PROG_TYPE_LSM, BPF_LSM_MAC,
                                   KIMGLOCK_ID, LSM_LOCKED_DOWN_ID);
                collect_event_operation(event, what);
        }

        /* If Restricted permission model then return now */
        blocked = *val;
        switch (blocked) {
        case BPFLOCK_P_RESTRICTED:
                return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_restricted, debug);
        case BPFLOCK_P_ALLOW:
                reason = reason_allow;
                ret = 0;
                break;
        case BPFLOCK_P_BASELINE:
                /* If not allowed then fail now do not give exception for non privileged */
                if (!is_task_allowed(event, 0))
                        return report(event, LSM_LOCKED_DOWN_ID, -EPERM,
                                      reason_baseline_restricted, debug);

                reason = reason_baseline;
                ret = 0;
                break;
        default:
                /* Guard */
                return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_restricted, debug);
        }

        k = what;
        /* If what access is not found then return with default */
        val = bpf_map_lookup_elem(&kimglock_block_map, &k);
        if (!val)
                return report(event, LSM_LOCKED_DOWN_ID, ret, reason, debug);

        blocked = *val;
        if (blocked == KIMGLOCK_BLOCK_OP)
                return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_baseline_restricted, debug);

        return report(event, LSM_LOCKED_DOWN_ID, ret, reason, debug);
}

SEC("lsm/locked_down")
int BPF_PROG(kimg_lockdown, enum lockdown_reason what, int ret)
{
        if (ret != 0)
                return ret;

        /* Let's ignore for now tracefs to not generate more
         * events and allow everything after KCORE */
        if (what == LOCK_KIMG_TRACEFS || what > LOCK_KIMG_KCORE)
                return ret;

        return check_kimg_perm(what);
}

static const char _license[] SEC("license") = "GPL";
