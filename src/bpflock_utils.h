// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_UTILS_H
#define __BPFLOCK_UTILS_H

#define LOG_BPFLOCK "bpflock"

#define LSM_BPF_PATH "/sys/kernel/security/lsm"

int is_lsmbpf_supported();
char *strstr(const char *s1, const char *s2);

#endif /* __BPFLOCK_UTILS_H */
