// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 *Copyright (C) 2021 Djalal Harouni
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bpflock_utils.h"

int is_lsmbpf_supported()
{
	int err = 0, fd;
	char buf[512];
	ssize_t len;
	char *c;

	fd = open(LSM_BPF_PATH, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "%s: error opening /sys/kernel/security/lsm ('%s') - "
		       "securityfs not mounted?\n",
		       LOG_BPFLOCK, strerror(-err));
		return err;
	}

	len = read(fd, buf, sizeof(buf));
	if (len == -1) {
		err = -errno;
		fprintf(stderr, "%s: error reading /sys/kernel/security/lsm: %s\n",
		       LOG_BPFLOCK, strerror(-err));
		close(fd);
		return err;
	}

	close(fd);
	buf[sizeof(buf)-1] = '\0';
	c = strstr(buf, "bpf");
	if (!c) {
		fprintf(stderr, "%s: error BPF LSM not loaded - make sure CONFIG_LSM or lsm kernel "
		       "param includes 'bpf'!\n", LOG_BPFLOCK);
		return -EINVAL;
	}

	return err;
}
