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
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include "bpflock_bpf_defs.h"
#include "disablebpf.h"

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8);
        __type(key, uint32_t);
        __type(value, uint32_t);
} disablebpf_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8);
        __type(key, uint32_t);
        __type(value, struct bl_stat);
} disablebpf_ns_map SEC(".maps");

int pinned_bpf = 0;

static __always_inline bool is_init_mnt_ns(void)
{
        struct task_struct *task;
        struct nsproxy *nsp;
        struct bl_stat *st;
        unsigned long ino = 0;
        uint32_t k = 1;

        /*
         * If we fail to read stat namespaces then just assume
         * not same namespaces.
         */
        st = bpf_map_lookup_elem(&disablebpf_ns_map, &k);
        if (!st)
                return false;

        task = (struct task_struct *)bpf_get_current_task();
        bpf_core_read(&nsp, sizeof(nsp), &task->nsproxy);
        ino = BPF_CORE_READ(nsp, mnt_ns, ns.inum);

        /*
         * For now lets compare only ino which is the ns.inum
         * on proc.
         */
        return ino == PROC_DYNAMIC_FIRST && ino == st->st_ino;
}

SEC("lsm/locked_down")
int BPF_PROG(bpflock_disablebpf_bpf_write, enum lockdown_reason what, int ret)
{
        uint32_t *val, blocked = 0, allowed = 0;
        uint32_t k = BPFLOCK_BPF_PERM;

        if (ret != 0 || what != LOCKDOWN_BPF_WRITE_USER || !pinned_bpf)
		return ret;

        val = bpf_map_lookup_elem(&disablebpf_map, &k);
        if (!val)
		return 0;

        blocked = *val;
        if (blocked == BPFLOCK_BPF_DENY)
                return -EACCES;
        else if (blocked == BPFLOCK_BPF_ALLOW)
		return 0;

        /* If restrict and not in init namespace deny access */
        if (!is_init_mnt_ns())
                return -EACCES;

        k = BPFLOCK_BPF_ALLOW_OP;

        /* If not found deny access */
        val = bpf_map_lookup_elem(&disablebpf_map, &k);
        if (!val)
                return -EACCES;

        allowed = *val;
        if (allowed & BPFLOCK_BPF_WRITE)
                return 0;

        return -EACCES;
}

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

                /* If restrict and not in init namespace deny access */
                if (blocked == BPFLOCK_BPF_RESTRICT && !is_init_mnt_ns())
                        return -EACCES;

                k = BPFLOCK_BPF_OP;

                /*
		   Check if a list of blocked operations was set,
		   if not then allow BPF commands.
		   This covers both restrict and allow permissions.
		 */
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
