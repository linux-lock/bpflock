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
#include "bpflock_bpf_defs.h"
#include "kmodlock.h"

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8);
        __type(key, uint32_t);
        __type(value, uint32_t);
} disablemods_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8);
        __type(key, uint32_t);
        __type(value, struct bl_stat);
} disablemods_ns_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1);
        __type(key, uint32_t);
        __type(value, struct sb_elem);
} disablemods_sb_map SEC(".maps");

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
        uint32_t k = BPFLOCK_KM_NS;

        /*
         * If we fail to read stat namespaces then just assume
         * not same namespaces.
         */
        st = bpf_map_lookup_elem(&disablemods_ns_map, &k);
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

static __always_inline struct sb_elem *lookup_sb_elem(void)
{
        uint32_t key = BPFLOCK_KM_SB;
        return bpf_map_lookup_elem(&disablemods_sb_map, &key);
}

static __always_inline long prepare_sb_elem(void)
{
        struct sb_elem sb_init = {}, *sb_val;
        uint32_t key = BPFLOCK_KM_SB;

        sb_val = bpf_map_lookup_elem(&disablemods_sb_map, &key);
        if (sb_val)
                return 0;

        return bpf_map_update_elem(&disablemods_sb_map, &key, &sb_init, BPF_NOEXIST);
}

static __always_inline struct super_block *bpf_read_sb_from_file(struct file *file)
{
        struct vfsmount *mnt;

        mnt = BPF_CORE_READ(file, f_path.mnt);
        return BPF_CORE_READ(mnt, mnt_sb);
}

static __always_inline int module_rootfs_check(struct file *file,
                enum kernel_read_file_id id, bool contents)
{
        struct sb_elem *sb_root_val;
        struct super_block *sb;
        unsigned long sdev;
        int ret;

        /* If we do not have full content nor file context we deny */
        if (!contents || !file) {
                /* TODO log operation */
                return -EPERM;
        }

        sb = bpf_read_sb_from_file(file);
        sb_root_val = lookup_sb_elem();
        if (!sb_root_val)
                return -EPERM;

        /* Set sb root here if it was not set */
        bpf_spin_lock(&sb_root_val->lock);
        if (!sb_root_val->sb_root && sb_root_val->freed == 0)
                sb_root_val->sb_root = sb;
        bpf_spin_unlock(&sb_root_val->lock);

        /* Deny if the module is loaded from another block or block was freed. */
        if (!sb_root_val->sb_root || sb_root_val->freed || sb_root_val->sb_root != sb) {
                return -EPERM;
        }

        return 0;
}

static __always_inline int module_load_check(int blocked_op)
{
        uint32_t *val, blocked = 0;
        uint32_t k = BPFLOCK_KM_PERM;

        val = bpf_map_lookup_elem(&disablemods_map, &k);
        if (!val)
                return 0;

	blocked = *val;
	if (blocked == BPFLOCK_KM_DENY)
		return -EPERM;

        /* If restrict and not in init pid namespace deny access */
        if (blocked == BPFLOCK_KM_RESTRICT && !is_init_pid_ns())
		return -EPERM;

        k = BPFLOCK_KM_OP;
        val = bpf_map_lookup_elem(&disablemods_map, &k);
        if (!val)
                return 0;

	blocked = *val;
	if (blocked & blocked_op)
		return -EPERM;

        return 0;
}

SEC("lsm/sb_free_security")
void BPF_PROG(km_sb_free, struct super_block *mnt_sb)
{
        struct sb_elem *sb_root_val;

        /* This was never registered as root sb */
        sb_root_val = lookup_sb_elem();
        if (!sb_root_val)
                return;

        /*
         Lets be consistent with loadpin:
         disable sb_root and deactivate module loading
        */
        bpf_spin_lock(&sb_root_val->lock);
        if (sb_root_val->sb_root == mnt_sb)
                sb_root_val->freed = 1;
                sb_root_val->sb_root = NULL;
        bpf_spin_unlock(&sb_root_val->lock);
}

SEC("lsm/locked_down")
int BPF_PROG(km_locked_down, enum lockdown_reason what, int ret)
{
        uint32_t blocked_op = 0;

        if (ret != 0 )
                return ret;

        if (what == LOCKDOWN_MODULE_SIGNATURE)
		blocked_op = BPFLOCK_KM_UNSIGNED;
	else if (what == LOCKDOWN_MODULE_PARAMETERS)
		blocked_op = BPFLOCK_KM_UNSAFEMOD;
	else
                return 0;

        ret = module_load_check(blocked_op);
        if (ret < 0)
                return ret;

        return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(km_autoload, char *kmod_name, int ret)
{
        if (ret != 0)
                return ret;

        ret = module_load_check(BPFLOCK_KM_AUTOLOAD);
        if (ret < 0)
                return ret;

	return 0;
}

static int kmod_from_file(struct file *file,
                enum kernel_read_file_id id, bool contents)
{
        struct super_block *sb;
        uint32_t key = BPFLOCK_KM_SB;
        unsigned long sdev;
        int ret;

        prepare_sb_elem();

        ret = module_load_check(BPFLOCK_KM_LOAD);
        if (ret < 0)
                return ret;

        ret = module_rootfs_check(file, id, contents);
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

	switch (id) {
	case READING_MODULE:
		ret = kmod_from_file(file, READING_MODULE, contents);
		break;
	default:
		break;
	}

	return ret;
}

SEC("lsm/kernel_load_data")
int BPF_PROG(km_load_data, enum kernel_read_file_id id,
             bool contents, int ret)
{
        if (ret != 0)
                return ret;

	switch (id) {
	case LOADING_MODULE:
		ret = kmod_from_file(NULL, (enum kernel_read_file_id) LOADING_MODULE, contents);
		break;
	default:
		break;
	}

	return ret;
}

static const char _license[] SEC("license") = "GPL";