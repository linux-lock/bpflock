// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include "bpflock_bpf_defs.h"
#include "bpflock_shared_defs.h"
#include "bpfrestrict.h"

#define DBPF_PROGRAMS 2
#define DBPF_WRITE_USER 16

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8);
        __type(key, uint32_t);
        __type(value, uint32_t);
} bpfrestrict_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8);
        __type(key, uint32_t);
        __type(value, struct bl_stat);
} bpfrestrict_ns_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
} bpflock_events SEC(".maps");

int pinned_bpf = 0;

static __always_inline bool is_init_pid_ns(void)
{
        struct task_struct *current;
        unsigned long id = 0;

        current = (struct task_struct *)bpf_get_current_task();
        id = BPF_CORE_READ(current, nsproxy, pid_ns_for_children, ns.inum);

        return id == (unsigned long)PROC_PID_INIT_INO;
}

static __always_inline bool is_init_mnt_ns(void)
{
        struct task_struct *current;
        struct bl_stat *st;
        unsigned long ino = 0;
        uint32_t k = 1;

        /*
         * If we fail to read stat namespaces then just assume
         * not same namespaces.
         */
        st = bpf_map_lookup_elem(&bpfrestrict_ns_map, &k);
        if (!st)
                return false;

        current = (struct task_struct *)bpf_get_current_task();
        ino = BPF_CORE_READ(current, nsproxy, mnt_ns, ns.inum);

        /*
         * For now lets compare only ino which is the ns.inum
         * on proc.
         */
        return ino == (unsigned long)PROC_DYNAMIC_FIRST && ino == st->st_ino;
}

static __always_inline int report(const char *op, const int ret, int reason)
{
        uint64_t id;
        static struct event info;

        id = bpf_get_current_pid_tgid();
        info.pid = id >> 32;

        bpf_get_current_comm(&info.comm, sizeof(info.comm));

        bpf_printk("bpflock bpf=bpfrestrict pid=%lu comm=%s event=%s\n",
                   info.pid, info.comm, op);
        bpf_printk("bpflock bpf=bpfrestrict pid=%lu event=%s status=%s\n",
                   info.pid, op, get_reason_str(ret, reason));

        return ret;
}

SEC("lsm/bpf")
int BPF_PROG(bpfrestrict, int cmd, union bpf_attr *attr,
             unsigned int size, int ret)
{
        uint32_t *val, blocked = 0, op_blocked = 0;
        uint32_t k = BPFLOCK_BPF_PERM;

        if (ret != 0)
                return ret;

        if (pinned_bpf == DBPF_PROGRAMS) {
                val = bpf_map_lookup_elem(&bpfrestrict_map, &k);
                if (!val)
                        return ret;

                blocked = *val;
                if (blocked == BPFLOCK_P_RESTRICTED)
                        return report("bpf()", -EPERM, reason_restricted);

                if (blocked == BPFLOCK_P_ALLOW)
                        return report("bpf()", 0, reason_allow);

                /* If baseline and not in init pid namespace deny access */
                if (blocked == BPFLOCK_P_BASELINE && !is_init_pid_ns())
                        return report("bpf() from non init pid namespace", -EPERM, reason_baseline);

                k = BPFLOCK_BPF_OP;

                /*
                 * Check if a list of blocked operations was set,
                 * if not then allow BPF commands.
                 * This covers both restrict and allow permissions.
                 */
                val = bpf_map_lookup_elem(&bpfrestrict_map, &k);
                if (!val)
                        return report("bpf()", 0, reason_baseline_allowed);

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
                        return report("bpf() blocked cmd", -EPERM, reason_baseline_restricted);

                return report("bpf() allowed cmd", 0, reason_baseline);

        } else if (cmd == BPF_OBJ_PIN) {
                pinned_bpf += 1;
        }

        return ret;
}

SEC("lsm/locked_down")
int BPF_PROG(bpfrestrict_bpf_write, enum lockdown_reason what, int ret)
{
        uint32_t *val, blocked = 0, reason = 0;
        uint32_t k = BPFLOCK_BPF_PERM;

        if (ret != 0 )
                return ret;

        if (what != DBPF_WRITE_USER || pinned_bpf != DBPF_PROGRAMS)
                return ret;

        val = bpf_map_lookup_elem(&bpfrestrict_map, &k);
        if (!val)
                return ret;

        blocked = *val;
        if (blocked == BPFLOCK_P_RESTRICTED)
                return report("bpf() write user", -EPERM, reason_restricted);

        if (blocked == BPFLOCK_P_ALLOW)
                return report("bpf() write user", 0, reason_allow);

        /* If restrict and not in init pid namespace, then deny access */
        if (blocked == BPFLOCK_P_BASELINE && !is_init_pid_ns())
                return report("bpf() write user from non init pid namespace", -EPERM, reason_baseline);

        k = BPFLOCK_BPF_OP;

        /* If not block access is not found then allow */
        val = bpf_map_lookup_elem(&bpfrestrict_map, &k);
        if (!val)
                return report("bpf() write user", 0, reason_baseline);

        blocked = *val;
        if (blocked & BPFLOCK_BPF_WRITE)
                return report("bpf() write user", -EPERM, reason_baseline_restricted);

        return report("bpf() write user", 0, reason_baseline_allowed);
}

static const char _license[] SEC("license") = "GPL";
