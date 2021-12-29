// SPDX-License-Identifier: GPL-2.0

/*
 * TODO this is still work in progress:
 * this restricts some predefined file systems system wide for Embedded
 * devices.
 *
 * Reference work: https://github.com/systemd/systemd/pull/18145
 *
 * If you want to restricted based systemd services.
 *
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/magic.h>


struct super_block {
        long unsigned int s_magic;
} __attribute__((preserve_access_index));

struct inode {
        struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
        struct inode *f_inode;
} __attribute__((preserve_access_index));


SEC("lsm/file_open")
int BPF_PROG(restrict_filesystems, struct file *file, int ret)
{
        unsigned long magic_number;
        uint32_t *value, *magic_map, zero = 0, *is_allow;

        if (ret != 0)
                return ret;

        BPF_CORE_READ_INTO(&magic_number, file, f_inode, i_sb, s_magic);

	/* TODO: make this configurable for Embedded systems */
	if (magic_number == CRAMFS_MAGIC ||
	   magic_number == CRAMFS_MAGIC_WEND ||
	   magic_number == DEBUGFS_MAGIC ||
	   magic_number == SECURITYFS_MAGIC ||
	   magic_number == RAMFS_MAGIC ||
	   magic_number == TMPFS_MAGIC ||
	   magic_number == SQUASHFS_MAGIC ||
	   magic_number == EXT2_SUPER_MAGIC ||
	   magic_number == EXT3_SUPER_MAGIC ||
	   magic_number == EXT4_SUPER_MAGIC ||
	   magic_number == OVERLAYFS_SUPER_MAGIC) {
		return 0;
	}

        return -EPERM;
}

char _license[] SEC("license") = "GPL";
