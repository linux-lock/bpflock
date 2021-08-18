// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

int blocked = 0;

SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr,
	     unsigned int size, int ret)
{
        if (ret != 0)
                return ret;

	/* We need to allow a single pin action to pin ourselves after attach */
	if (cmd == BPF_OBJ_PIN && !blocked) {
		blocked = 1;
		return 0;
	}
	return -EACCES;
}

char _license[] SEC("license") = "GPL";
