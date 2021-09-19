/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

 /*
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
        __uint(max_entries, 16);
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
        uint32_t *val, blocked = 0, op_blocked = 0;
        uint32_t k = BPFLOCK_BPF_PERM;

        if (ret != 0)
                return ret;

        if (pinned_bpf) {
                val = bpf_map_lookup_elem(&disablebpf_map, &k);
                if (!val)
                        return 0;

                blocked = *val;
                if (blocked == BPFLOCK_BPF_DENY)
                        return -EACCES;

                /* Filter allow too
                if (allowed == BPFLOCK_BPF_ALLOW)
                        return 0;
                */

                /* Here we just force restrict */
                k = BPFLOCK_BPF_OP;
                /* Check if a list of blocked operations was set, if not then allow BPF commands */
                val = bpf_map_lookup_elem(&disablebpf_map, &k);
                if (!val)
                        return 0;

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
                        return -EACCES;

        } else if (cmd == BPF_OBJ_PIN) {
                pinned_bpf = 1;
        }

        return ret;
}

static const char _license[] SEC("license") = "GPL";