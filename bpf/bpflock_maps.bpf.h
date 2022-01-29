// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/* Shared maps between all programs */

#ifndef __BPFLOCK_SHARED_MAPS_H
#define __BPFLOCK_SHARED_MAPS_H

#include "bpflock_shared_defs.h"


/*
 * TODO these should be converted to LRU maps or
 * add dynamic tracking
 */

/*
 * Per container profile must be pinned by name
 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16384);
        __type(key, uint64_t);
        __type(value, struct cgroup_map_entry);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_cgroupmap SEC(".maps");

/* Per pidns profile */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16384);
        __type(key, unsigned int);
        __type(value, struct pidns_map_entry);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_pidnsmap SEC(".maps");

/* Per mntns profile */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16384);
        __type(key, unsigned int);
        __type(value, struct netns_map_entry);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_netnsmap SEC(".maps");

/* Per mntns profile */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16384);
        __type(key, unsigned int);
        __type(value, struct mntns_map_entry);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_mntnsmap SEC(".maps");

/* Output ringbuffer */
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpflock_events SEC(".maps");

#endif /* __BPFLOCK_SHARED_MAPS_H */
