/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
 * Implements access restrictions on bpf syscall, it supports following values:
 *   Per running context:
 *	- allow: bpf is allowed.
 *	- restrict: bpf is allowed only from processes that are in the initial mount
 *           namespace.
 *	- deny: deny bpf syscall and all its commands for all processes.
 *           Make sure to execute this program last during boot and after
 *           all necessary bpf programs have been loaded. For containers workload
 *           delete the pinned file and load it again after container initialization.
 *
 *   If bpf is allowed, then tasks can be restricted to the following commands: 
 *   - map_create: allow creation of bpf maps.
 *   - btf_load: allow loading BPF Type Format (BTF) metadata into the kernel.
 *   - prog_load: allow loading bpf programs.
 *   All other commands are allowed.
 *
 * To disable this program, delete the pinned file "/sys/fs/bpf/bpflock/disable-bpf",
 * re-executing will enable it again.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "disablebpf.h"

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 32);
        __type(key, uint32_t);
        __type(value, uint32_t);
} disablebpf_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16);
        __type(key, u64);
        __type(value, u64);
} disablebpf_env_map SEC(".maps");

int pinned_bpf = 0;

SEC("lsm/bpf")
int BPF_PROG(bpflock_disablebpf, int cmd, union bpf_attr *attr,
             unsigned int size, int ret)
{
        uint32_t *val, allowed = 0, op_allowed = 0;
        uint32_t k = BPFLOCK_BPF_PERM;

        if (ret != 0)
                return ret;

        if (pinned_bpf) {
                val = bpf_map_lookup_elem(&disablebpf_map, &k);
                if (!val)
                        return 0;

                allowed = *val;
                if (allowed == BPFLOCK_BPF_DENY)
                        return -EACCES;

                if (allowed == BPFLOCK_BPF_ALLOW)
                        return 0;

                /* Here we just force restrict */
                k = BPFLOCK_BPF_OP;
                /* Check if a list of allowed operations was set, if not then allow BPF commands */
                val = bpf_map_lookup_elem(&disablebpf_map, &k);
                if (!val)
                        return 0;

                allowed = *val;

                switch (cmd) {
                case BPF_PROG_LOAD:
                        op_allowed = allowed & BPFLOCK_PROG_LOAD;
                        break;
                case BPF_MAP_CREATE:
                        op_allowed = allowed & BPFLOCK_MAP_CREATE;
                        break;
                case BPF_BTF_LOAD:
                        op_allowed = allowed & BPFLOCK_BTF_LOAD;
                        break;
                default:
                        op_allowed = 1;
                        break;
                }

                if (allowed)
                        return 0;

                ret = -EACCES;

        } else if (cmd == BPF_OBJ_PIN) {
                pinned_bpf = 1;
        }

        return ret;
}

static const char _license[] SEC("license") = "GPL";