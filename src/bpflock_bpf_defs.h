/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_BPF_DEFS_H
#define __BPFLOCK_BPF_DEFS_H

#define BPFLOCK_NS_KEY  1

#define PROC_DYNAMIC_FIRST 0xF0000000U

struct bl_stat {
	unsigned long  st_dev;	/* Device.  */
	unsigned long  st_ino;	/* File serial number.  */
};

#endif /* __BPFLOCK_BPF_DEFS_H */
