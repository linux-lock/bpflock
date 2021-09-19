/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <bpf/bpf.h>
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

int pin_init_task_ns(int fd)
{
        struct stat id;
        uint32_t k = 1;
        int ret;

        ret = read_task_mnt_id("/proc/1/ns/mnt", &id);
        if (ret < 0)
                return ret;

        bpf_map_update_elem(fd, &k, &id, BPF_ANY);

        return 0;
}