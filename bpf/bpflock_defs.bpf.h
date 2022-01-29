// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_DEFS_BPF_H
#define __BPFLOCK_DEFS_BPF_H

#include <bpf/bpf_helpers.h>
#include "bpflock_shared_defs.h"
#include "bpflock_shared_object_ids.h"

#include "bpflock_maps.bpf.h"

struct bl_stat {
        unsigned long  st_dev;	/* Device.  */
        unsigned long  st_ino;	/* File serial number.  */
};

struct sb_elem {
        int freed;
        struct super_block *sb_root;
        struct bpf_spin_lock lock;
};

static __always_inline uint64_t get_event_id(uint32_t program_id, uint32_t id)
{
        return (id | ((uint64_t) program_id) << 32);
}

static __always_inline bool is_profile_allowed(int profile)
{
        return (profile == BPFLOCK_P_BASELINE || profile == BPFLOCK_P_ALLOW) ? true : false;
}

static __always_inline const char *get_reason_str(const int ret, int reason)
{
	switch (reason) {
	case reason_allow:
		return "allowed (privileged)";
	case reason_baseline_allowed:
		return "allowed (baseline)";
	case reason_baseline:
		return (ret < 0) ? "denied (baseline)" :
			"allowed (baseline)";
	case reason_baseline_restricted:
		return "denied (baseline)";
	case reason_restricted:
		return "denied (restricted)";
	}

        /* Return empty */
	return "";
}

static __always_inline bool is_mntns_allowed(struct bpf_map *map, uint32_t filter,
                                             struct process_event *event)
{
        unsigned int id;
        struct task_struct *task;
        struct mntns_map_entry *val_mntns;

	/* If filter does not match or can't read it then allow */
        if (!(filter & BPFLOCK_P_FILTER_MNTNS))
                return false;

        /* If we can't get event then do not block */
        if (event) {
                id = event->mntns_id;
        } else {
                task = (struct task_struct*)bpf_get_current_task();
                id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
        }

        val_mntns = bpf_map_lookup_elem(map, &id);
        if (!val_mntns)
                return false;

        if (is_profile_allowed(val_mntns->profile)) {
                if (event)
                        event->matched_filter |= BPFLOCK_P_FILTER_MNTNS;
                return true;
        }

        return false;
}

static __always_inline bool is_pidns_allowed(struct bpf_map *map, uint32_t filter,
					     struct process_event *event)
{
        unsigned int id;
        struct task_struct *task;
        struct pidns_map_entry *val_pidns;

	/* If filter does not match or can't read it then block it */
        if (!(filter & BPFLOCK_P_FILTER_PIDNS))
                return false;

        /* If we can't get event then do not block */
        if (event) {
                id = event->pidns_id;
        } else {
                task = (struct task_struct*)bpf_get_current_task();
                id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
        }

        val_pidns = bpf_map_lookup_elem(map, &id);
        if (!val_pidns)
                return false;

        if (is_profile_allowed(val_pidns->profile)) {
                if (event)
                        event->matched_filter |= BPFLOCK_P_FILTER_PIDNS;
                return true;
        }

        return false;
}

static __always_inline bool is_cgroup_allowed(struct bpf_map *map, uint32_t filter,
					      struct process_event *event, int cgrp_incestor_level)
{
        uint64_t id;
        struct cgroup_map_entry *val_cgroup;

	/* If filter does not match or can't read it then block */
        if (!(filter & BPFLOCK_P_FILTER_CGROUP))
                return false;

        /* If we can't get event then try again directly */
        if (event)
                id = event->cgroup_id;
        else
                id = bpf_get_current_cgroup_id();

        val_cgroup = bpf_map_lookup_elem(map, &id);
        if (val_cgroup && is_profile_allowed(val_cgroup->profile)) {
                if (event)
                        event->matched_filter |= BPFLOCK_P_FILTER_CGROUP;
                return true;
        }

        return false;        
}

static __always_inline void collect_event_types(struct process_event *event, int ptype,
                                                int attach, uint64_t eventid)
{
        if (event) {
                event->prog_type = ptype;
                event->attach_type = attach;
                event->pevent_id = eventid;
        }
}

static __always_inline void collect_event_uid(struct process_event *event)
{
        if (event) {
                uint64_t id = bpf_get_current_uid_gid();
                event->uid = (uid_t)id;
                event->gid = id >> 32;
        }
}

static __always_inline void collect_event_pid_info(struct process_event *event)
{
        if (event) {
                const char unsigned *p;
                struct task_struct *task;
                uint64_t id = bpf_get_current_pid_tgid();
                event->tgid = id >> 32;
                event->pid = (pid_t)id;

                task = (struct task_struct*)bpf_get_current_task();
                event->cgroup_id = bpf_get_current_cgroup_id();
                event->pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
                event->mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

                bpf_get_current_comm(&event->comm, sizeof(event->comm));
                /* racy... */
                if (event->tgid > 1) {
                        event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
                        p = (char unsigned *)BPF_CORE_READ(task, real_parent, comm);
                        bpf_probe_read_kernel_str(&event->pcomm, sizeof(event->pcomm), p);
                }
        }
}

static __always_inline void collect_event_info(struct process_event *event, int ptype,
                                                int attach, uint64_t eventid)
{
        if (!event)
                return;

        collect_event_types(event, ptype, attach, eventid);
        collect_event_uid(event);
        collect_event_pid_info(event);
}

static __always_inline void collect_info_output(struct bpf_map *map, struct process_event *event)
{
        bpf_ringbuf_output(map, event, sizeof(*event), 0);
}

static __always_inline int report(struct process_event *event, const char *op,
                                  const int ret, int reason, bool debug)
{
        pid_t pid;
        uint64_t id;
        char comm[TASK_COMM_LEN];

        if (event) {
                event->retval = ret;
                event->reason = reason;

                collect_info_output((struct bpf_map *)&bpflock_events, event);
        }

        /* If debug send bpf_printk events */
        if (debug) {
                const char unsigned *p;
                struct task_struct *task;

                id = bpf_get_current_pid_tgid();
                pid = id >> 32;
                bpf_get_current_comm(&comm, sizeof(comm));

                task = (struct task_struct*)bpf_get_current_task();
                bpf_printk("bpflock event=%s  pid=%d  comm=%s\n", op, pid, comm);

                p = (char unsigned *)BPF_CORE_READ(task, real_parent, comm);
                bpf_probe_read_kernel_str(&comm, sizeof(comm), p);

                bpf_printk("bpflock event=%s  pid=%d  parent_comm=%s\n", op, pid, comm);
                bpf_printk("bpflock event=%s  pid=%d  status=%s\n",
                           op, pid, get_reason_str(ret, reason));
        }
        return ret;
}

#endif /* __BPFLOCK_DEFS_BPF_H */
