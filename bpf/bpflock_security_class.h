/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef __BPFLOCK_SECURITY_CLASS_H
#define __BPFLOCK_SECURITY_CLASS_H

struct bpflock_class_map {
        const char *name;
        const char *pin_path;
        const char *perms_str[sizeof(unsigned) * 8 + 1];
        const int32_t perms_int[sizeof(unsigned) * 8 + 1];
};

struct bpflock_class_prog_link {
        const char *name;
        const char *link;
} bpflock_class_prog_link_t;

#endif /* __BPFLOCK_SECURITY_CLASS_H */