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
#include "bpfrestrict.h"

/* Count current bpf programs here */
#define BPF_PROGRAMS_COUNT 2

/* Lockdown BPF write user */
#define LOCKDOWN_BPF_WRITE_USER 16

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, uint32_t);
        __type(value, struct process_event);
} bpfrestrict_event_storage SEC(".maps");

/*
 * map that holds the profile for bpfrestrict and allowed/blocked
 * operations + filter and other passed arguments.
 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 5);
        __type(key, uint32_t);
        __type(value, uint32_t);
} bpfrestrict_args_map SEC(".maps");

int pinned_bpf = 0;
const volatile bool debug = false;

/* readonly test var to enforce profile and avoid bpf maps... */
const volatile enum bpflock_profile global_profile = 0;

static __always_inline bool is_task_allowed(struct process_event *event,
                                            int cgrp_incestor_level)
{
        uint32_t *filter;
        uint32_t k = BPFRESTRICT_MAPS_FILTER;

        /* By default pass the corresponding filter */
        if (is_pidns_allowed((struct bpf_map *)&bpflock_pidnsmap,
                             BPFLOCK_P_FILTER_PIDNS, event))
                return true;

        if (is_netns_allowed((struct bpf_map *)&bpflock_netnsmap,
                             BPFLOCK_P_FILTER_NETNS, event))
                return true;

        filter = bpf_map_lookup_elem(&bpfrestrict_args_map, &k);
        /* If fitler then match the cgroupmap */
        if (filter && *filter > 0) {
                if (is_cgroup_allowed((struct bpf_map *)&bpflock_cgroupmap,
                                      *filter, event, cgrp_incestor_level))
                        return true;
        }

        return false;
}

SEC("lsm/bpf")
int BPF_PROG(bpfrestrict_bpf, int cmd, union bpf_attr *attr,
             unsigned int size, int ret)
{
        uint32_t *val, blocked = 0, op_blocked = 0;
        uint32_t k = BPFRESTRICT_PROFILE;
        struct process_event *event;
        uint32_t zero = 0;
        int reason = 0;

        if (ret != 0)
                return ret;

        if (pinned_bpf == BPF_PROGRAMS_COUNT) {
                val = bpf_map_lookup_elem(&bpfrestrict_args_map, &k);
                if (!val)
                        return ret;

                event = bpf_map_lookup_elem(&bpfrestrict_event_storage, &zero);
                /* Do not fail as we have to take decisions */
                if (event)
                        collect_event_info(event, BPF_PROG_TYPE_LSM, BPF_LSM_MAC,
                                           BPFRESTRICT_ID, LSM_BPF_ID);

                /* Check the global profile */
                blocked = *val;
                if (blocked == BPFLOCK_P_RESTRICTED)
                        return report(event, LSM_BPF_ID, -EPERM, reason_restricted, debug);

                if (blocked == BPFLOCK_P_ALLOW) {
                        /* Save reason and check later if operation is blocked */
                        reason = reason_allow;
                        ret = 0;
                } else if (blocked == BPFLOCK_P_BASELINE) {
                        /* If baseline then check the map filters */
                        if (!is_task_allowed(event, 0))
                                return report(event, LSM_BPF_ID, -EPERM, reason_baseline, debug);
                        reason = reason_baseline;
                        ret = 0;
                } else {
                        /* Guard */
                        return report(event, LSM_BPF_ID, -EPERM, reason_restricted, debug);
                }

                /*
                 * Check if a list of blocked operations was set,
                 * if not then allow BPF commands.
                 * This covers both restrict and allow permissions.
                 */
                k = BPFRESTRICT_BLOCK_OP;
                val = bpf_map_lookup_elem(&bpfrestrict_args_map, &k);
                if (!val)
                        return report(event, LSM_BPF_ID, ret, reason, debug);

                blocked = *val;

                switch (cmd) {
                case BPF_PROG_LOAD:
                        op_blocked = blocked & BPFLOCK_PROG_LOAD;
                        break;
                case BPF_MAP_CREATE:
                        op_blocked = blocked & BPFLOCK_MAP_CREATE;
                        break;
                case BPF_BTF_LOAD:
                        op_blocked = blocked & BPFLOCK_BTF_LOAD;
                        break;
                default:
                        op_blocked = 0;
                        break;
                }

                if (op_blocked)
                        return report(event, LSM_BPF_ID, -EPERM,
                                       reason_baseline_restricted, debug);

                return report(event, LSM_BPF_ID, ret, reason, debug);

        } else if (cmd == BPF_OBJ_PIN) {
                pinned_bpf += 1;
        }

        return ret;
}

SEC("lsm/locked_down")
int BPF_PROG(bpfrestrict_locked_down, enum lockdown_reason what, int ret)
{
        uint32_t *val, blocked = 0, reason = 0;
        struct process_event *event;
        uint32_t k = BPFRESTRICT_PROFILE;
        uint32_t zero = 0;

        if (ret != 0 )
                return ret;

        if (what != LOCKDOWN_BPF_WRITE_USER || pinned_bpf != BPF_PROGRAMS_COUNT)
                return ret;

        val = bpf_map_lookup_elem(&bpfrestrict_args_map, &k);
        if (!val)
                return ret;

        event = bpf_map_lookup_elem(&bpfrestrict_event_storage, &zero);
        /* Do not fail as we have to take decisions */
        if (event)
                collect_event_info(event, BPF_PROG_TYPE_LSM, BPF_LSM_MAC,
                                   BPFRESTRICT_ID, LSM_LOCKED_DOWN_ID);

        blocked = *val;
        if (blocked == BPFLOCK_P_RESTRICTED)
                return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_restricted, debug);

        if (blocked == BPFLOCK_P_ALLOW) {
                reason = reason_allow;
                ret = 0;
        } else if (blocked == BPFLOCK_P_BASELINE) {
                if (!is_task_allowed(event, 0))
                        return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_baseline, debug);
                
                reason = reason_baseline;
                ret = 0;
        } else {
                /* Guard */
                return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_restricted, debug);
        }

        k = BPFRESTRICT_BLOCK_OP;
        /* If block access is not found then:  allow */
        val = bpf_map_lookup_elem(&bpfrestrict_args_map, &k);
        if (!val)
                return report(event, LSM_LOCKED_DOWN_ID, ret, reason, debug);

        /* If block BPF Write then fail */
        blocked = *val;
        if (blocked & BPFLOCK_BPF_WRITE)
                return report(event, LSM_LOCKED_DOWN_ID, -EPERM, reason_baseline_restricted, debug);

        return report(event, LSM_LOCKED_DOWN_ID, ret, reason, debug);
}

static const char _license[] SEC("license") = "GPL";
