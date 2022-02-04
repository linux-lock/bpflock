// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Copyright (C) 2021 Djalal Harouni
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpflock_shared_defs.h"
#include "bpflock_utils.h"

size_t strv_length(char * const *l)
{
        size_t n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char *strv_env_get_n(char **l, const char *name, size_t k, unsigned flags)
{
        char **i;
        const char *t;

        if (!name)
                return NULL;

        if (k <= 0)
                return NULL;

        STRV_FOREACH_BACKWARDS(i, l)
                if ((strncmp(*i, name, k) == 0) && (*i)[k] == '=')
                        return *i + k + 1;

        t = strndupa(name, k);
        return getenv(t);
}

char *strv_env_get(char **l, const char *name)
{
        if (!name)
                return NULL;

        return strv_env_get_n(l, name, strlen(name), 0);
}

int is_lsmbpf_supported()
{
        int err = 0, fd;
        char buf[512];
        ssize_t len;
        char *c;

        fd = open(LSM_BPF_PATH, O_RDONLY);
        if (fd < 0) {
                err = -errno;
                fprintf(stderr, "%s: error opening '/sys/kernel/security/lsm' ('%s') - "
                       "securityfs not mounted?\n",
                       LOG_BPFLOCK, strerror(-err));
                return err;
        }

        memset(buf, 0, sizeof(buf));
        len = read(fd, buf, sizeof(buf) - 1);
        if (len < 0) {
                err = -errno;
                fprintf(stderr, "%s: error reading '/sys/kernel/security/lsm': %s\n",
                       LOG_BPFLOCK, strerror(-err));
                goto out;
        } else if (len < 3) {
                err = -EINVAL;
                fprintf(stderr, "%s: failed to read '/sys/kernel/security/lsm' invalid data.\n",
                       LOG_BPFLOCK);
                goto out;
        }

        c = strstr(buf, "bpf");
        if (!c) {
                fprintf(stderr, "%s: error BPF LSM not loaded - make sure CONFIG_LSM or lsm kernel "
                       "param includes 'bpf'!\n", LOG_BPFLOCK);
                err = -EINVAL;
        }

out:
        close(fd);
        return err;
}

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = PATH_MAX;

        for (;;) {
                char *c = NULL;
                ssize_t n;

                c = malloc(sizeof(char) * (l+1));
                if (!c)
                        return -ENOMEM;

                n = readlinkat(fd, p, c, l);
                if (n < 0) {
                        free(c);
                        return -errno;
                }

                if ((size_t) n < l) {
                        c[n] = 0;
                        *ret = TAKE_PTR(c);
                        free(c);
                        return 0;
                }

                if (l > (SSIZE_MAX-1)/2) {
                        /* readlinkat() returns an ssize_t, and we want an extra byte for a
                         * trailing NUL, hence do an overflow check relative to SSIZE_MAX-1
                         * here */
                        free(c);
                        return -EFBIG;
                }

                l *= 2;
        }
}

int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}

int readlink_value(const char *p, char **ret)
{
        char *link = NULL;
        char *value;
        int r;

        r = readlink_malloc(p, &link);
        if (r < 0)
                return r;

        value = basename(link);
        if (!value) {
                r = -ENOENT;
                goto out;
        }

        value = strdup(value);
        if (!value) {
                r = -ENOMEM;
                goto out;
        }

out:
        *ret = value;
        free(link);
        return r;
}

int read_process_env(const char *path, char **ret)
{
        return readlink_malloc(path, ret);
}

int read_task_mnt_id(const char *path, struct stat *st)
{
        if (stat(path, st) < 0)
                return -errno;

        return 0;
}

int stat_sb_root(struct stat *st)
{
        if (stat("/", st) < 0)
                return -errno;

        return 0;
}

static void sanitize_pin_path(char *s)
{
        /* bpffs disallows periods in path names */
        while (*s) {
                if (*s == '.')
                        *s = '_';
                s++;
        }
}

int push_host_init_ns(struct bpf_map *pidnsmap)
{
        int fd;
        uint64_t key;
        static struct pidns_map_entry init_pidns_entry = {
                BPFLOCK_P_ALLOW,
        };

        fd = bpf_map__fd(pidnsmap);
        if (fd < 0)
                return fd;

        key = INIT_PIDNS_ID_INO;
        bpf_map_update_elem(fd, &key, &init_pidns_entry, BPF_NOEXIST);

        return 0;
}

int bpflock_bpf_map__set_pin_path(struct bpf_map *map, const char *prefix)
{
        int len, err;
        char path[PATH_MAX];

        if (!prefix)
                return -EINVAL;

        if (strlen(prefix) > NAME_MAX)
                return -ENAMETOOLONG;

        len = snprintf(path, sizeof(path), "%s/%s", prefix, bpf_map__name(map));
        if (len < 0)
                return -EINVAL;
        else if (len >= PATH_MAX)
                return -ENAMETOOLONG;

        sanitize_pin_path(path);
        err = bpf_map__set_pin_path(map, path);
        if (err)
                return err;

        return 0;
}

/* Assign an fd of an already loaded map so we can re-use it */
int bpf_assign_fd_to_map(struct bpf_map *map)
{
        int err = 0, fd;
        const char *path;

        if (!map)
                return -EINVAL;

        path = bpf_map__pin_path(map);
        if (!path)
                return -EINVAL;

        /* Lets use directly obj get */
        fd = bpf_obj_get(path);
        if (fd > 0) {
                err = bpf_map__reuse_fd(map, fd);
                close(fd);
        }

        return err;
}

int bpf_reuse_shared_maps(struct bpf_object *obj)
{
        struct bpf_map *map;
        int err;

        if (!obj)
                return -EINVAL;

        map = bpf_object__find_map_by_name(obj, SHARED_PIDNSMAP);
        err = libbpf_get_error(map);
        if (err)
                return err;

        err = bpf_assign_fd_to_map(map);
        if (err < 0)
                return err;

        map = bpf_object__find_map_by_name(obj, SHARED_CGROUPMAP);
        err = libbpf_get_error(map);
        if (err)
                return err;

        err = bpf_assign_fd_to_map(map);
        if (err < 0)
                return err;

        map = bpf_object__find_map_by_name(obj, SHARED_NETNSMAP);
        err = libbpf_get_error(map);
        if (err)
                return err;

        err = bpf_assign_fd_to_map(map);
        if (err < 0)
                return err;

        map = bpf_object__find_map_by_name(obj, SHARED_MNTNSMAP);
        err = libbpf_get_error(map);
        if (err)
                return err;

        err = bpf_assign_fd_to_map(map);
        if (err < 0)
                return err;

        map = bpf_object__find_map_by_name(obj, SHARED_EVENTS);
        err = libbpf_get_error(map);
        if (err)
                return err;

        err = bpf_assign_fd_to_map(map);
        if (err < 0)
                return err;

        return 0;
}

int bpflock_bpf_object__pin_maps(struct bpf_object *obj, const char *path)
{
        struct bpf_map *map;
        int err, pinned = 0;

        if (!obj)
                return -ENOENT;

        bpf_object__for_each_map(map, obj) {
                const char *pin_path = bpf_map__pin_path(map);

                if (path && !pin_path) {
                        err = bpflock_bpf_map__set_pin_path(map, path);
                        if (err < 0)
                                goto err_unpin_maps;
                }
                pin_path = bpf_map__pin_path(map);
                if (!pin_path)
                        continue;

                err = bpf_map__pin(map, pin_path);
                if (err < 0)
                        goto err_unpin_maps;

                /* We must at least pin some specific maps */
                pinned++;
        }

        if (!pinned) {
                err = -ENOENT;
                goto err_unpin_maps;
        }

        return 0;

err_unpin_maps:
        while ((map = bpf_object__prev_map(obj, map))) {
                if (bpf_map__pin_path(map) == NULL)
                        continue;

                bpf_map__unpin(map, NULL);
        }

        return err;
}

int bpflock_bpf_object__pin(struct bpf_object *obj, const char *path)
{
        int err;

        err = bpflock_bpf_object__pin_maps(obj, path);
        if (err)
                return err;

        err = bpf_object__pin_programs(obj, path);
        if (err) {
                bpf_object__unpin_maps(obj, path);
                return err;
        }

        return 0;
}