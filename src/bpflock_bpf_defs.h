/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_BPF_DEFS_H
#define __BPFLOCK_BPF_DEFS_H

struct bl_stat {
	unsigned long  st_dev;	/* Device.  */
	unsigned long  st_ino;	/* File serial number.  */
};

#endif /* __BPFLOCK_BPF_DEFS_H */
