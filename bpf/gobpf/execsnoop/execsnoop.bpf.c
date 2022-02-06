// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Derivered from https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.bpf.c

/*
 * Copyright (C) 2022 Djalal Harouni
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <bpflock_defs.bpf.h>

#include "execsnoop.h"

const volatile bool ignore_failed = true;
const volatile bool debug = false;
static const struct process_event empty_event = {};

/* TODO: improve hash management */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, pid_t);
        __type(value, struct process_event);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_execsnoop_storage SEC(".maps");

/*
 * map that holds the profile for execsnoop
 * operations + filter and other passed arguments.
 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 5);
        __type(key, uint32_t);
        __type(value, uint32_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_execsnoop_args SEC(".maps");

static __always_inline bool is_task_traced(struct process_event *event, uint32_t traced,
                                           int cgrp_incestor_level)
{
        /* We only trace by filter here */
        uint32_t filter = BPFLOCK_P_FILTER_CGROUP;

        if (traced == EXECSNOOP_TRACE_ALL)
                return true;
        else if (traced == EXECSNOOP_TRACE_BY_FILTER)
                return is_cgroup_allowed((struct bpf_map *)&bpflock_cgroupmap,
                                         filter, event, cgrp_incestor_level);

        return false;
}

static __always_inline struct process_event *get_task_event()
{
        u64 id;
        pid_t pid;
        uint32_t *val, k = EXECSNOOP_TRACE_TARGET;
        struct process_event *event;

        val = bpf_map_lookup_elem(&bpflock_execsnoop_args, &k);
        if (!val)
                return NULL;

        if (*val != EXECSNOOP_TRACE_BY_FILTER && *val != EXECSNOOP_TRACE_ALL)
                return NULL;

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;
        if (bpf_map_update_elem(&bpflock_execsnoop_storage, &pid, &empty_event, BPF_NOEXIST))
                return NULL;

        /* Get event */
        event = bpf_map_lookup_elem(&bpflock_execsnoop_storage, &pid);
        if (!event)
                return NULL;

        /* We are not interested in this task */
        if (!is_task_traced(event, *val, 0)) {
                bpf_map_delete_elem(&bpflock_execsnoop_storage, &pid);
                return NULL;
        }

        return event;
}

static __always_inline struct process_event *process_event()
{
        u64 id;
        pid_t pid;
        struct process_event *event;

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;
        event = bpf_map_lookup_elem(&bpflock_execsnoop_storage, &pid);
        /* Check if this pid was traced */
        if (!event)
                return NULL;

        if (!event->program_id) {
                bpf_map_delete_elem(&bpflock_execsnoop_storage, &pid);
                return NULL;
        }

        /* This process is traced */
        collect_event_uid(event);
        collect_event_pid_info(event);

        return event;
}

static __always_inline int do_exit_execve(struct trace_event_raw_sys_exit *ctx, int eventid)
{
        int ret;
        struct process_event *event;

        event = process_event();
        if (!event)
                return 0;

        /* Execution failed */
        ret = ctx->ret;
        if (ret < 0)
                goto cleanup;

        collect_event_pid_comm(event, true);

cleanup:
        report(event, eventid, ret, 0, debug);

        bpf_map_delete_elem(&bpflock_execsnoop_storage, &event->pid);
        return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct trace_event_raw_sys_enter* ctx)
{
        struct process_event *event;

        event = get_task_event();
        if (!event)
                return 0;

        collect_event_types(event, BPF_PROG_TYPE_TRACING, 0,
                            EXECSNOOP_ID, SYSCALL_EXECVEAT_ID);

        /* TODO: collect fdpath/filename with kprobe from struct filename */

        return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
        struct process_event *event;

        event = get_task_event();
        if (!event)
                return 0;

        collect_event_types(event, BPF_PROG_TYPE_TRACING, 0,
                            EXECSNOOP_ID, SYSCALL_EXECVE_ID);
        bpf_probe_read_user_str(event->filename, sizeof(event->filename),
                                (const char *)ctx->args[0]);

        return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__syscalls__sys_exit_execveat(struct trace_event_raw_sys_exit* ctx)
{
        do_exit_execve(ctx, SYSCALL_EXECVEAT_ID);
        return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
        do_exit_execve(ctx, SYSCALL_EXECVE_ID);
        return 0;
}

char LICENSE[] SEC("license") = "GPL";
