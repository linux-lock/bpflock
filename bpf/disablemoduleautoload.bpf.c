// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

/*
   This blocks userspace from loading arbitrary kernel modules using
   the autoload feature.
*/

/*
   To test it:
	1. lsmod | grep ipip -
		ipip module is not loaded.
	2. sudo ip tunnel add mytun mode ipip remote 10.0.2.100 local 10.0.2.15 ttl 255
		add tunnel "tunl0" failed: No such device
	3. lsmod | grep ipip -
		ipip module was not loaded.
*/

SEC("lsm/kernel_module_request")
int BPF_PROG(kernel_module_request_hook, char *kmod_name, int ret)
{
        if (ret != 0)
                return ret;

	return -EPERM;
}

/* TODO: complete with kernel_read_file calls too */
SEC("lsm/kernel_read_file")
int BPF_PROG(kernel_read_modulefile, struct file *file,
	     enum kernel_read_file_id id, int ret)
{
        if (ret != 0)
                return ret;

	switch (id) {
	case READING_MODULE:
		ret = -EPERM;
		break;
	default:
		break;
	}

	return ret;
}

char _license[] SEC("license") = "GPL";
