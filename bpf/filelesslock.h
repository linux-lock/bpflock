// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Djalal Harouni
 */

#ifndef __BPFLOCK_FILELESSLOCK_H
#define __BPFLOCK_FILELESSLOCK_H

#include "bpflock_shared_object_ids.h"
#include "bpflock_security_class.h"

/* bpf security class */

#define LOG_FILELESSLOCK "filelesslock"

#define FILELESSLOCK_PROFILE     1
#define FILELESSLOCK_MAPS_FILTER 4
#define FILELESSLOCK_DEBUG       5

struct bpflock_class_map fileless_security_map = {
        "filelesslock",
        "/sys/fs/bpf/bpflock/filelesslock",
        { NULL },
        { 0 }
};

struct bpflock_class_prog_link fileless_prog_links[] = {
        {
                "bpflock_filelesslock",
                "/sys/fs/bpf/bpflock/filelesslock/filelesslock_bprm_creds_from_file_link",
        },
};

/* End of filelesslock security class */

#endif /* __BPFLOCK_FILESSLOCK_H */
