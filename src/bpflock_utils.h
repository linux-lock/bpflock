/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __BPFLOCK_UTILS_H
#define __BPFLOCK_UTILS_H

#include <sys/stat.h>

#define LOG_BPFLOCK "bpflock"

#define LSM_BPF_PATH            "/sys/kernel/security/lsm"
#define BPFLOCK_NS_MAP_PIN      "/sys/fs/bpf/bpflock/ns_map"

#define STRV_FOREACH_BACKWARDS(s, l)                                \
        for (s = ({                                                 \
                        typeof(l) _l = l;                           \
                        _l ? _l + strv_length(_l) - 1U : NULL;      \
                        });                                         \
             (l) && ((s) >= (l));                                   \
             (s)--)

/*
 * Takes inspiration from Rusts's Option::take() method: reads and returns a pointer, but at the same time resets it to
 * NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take
 * macro: introduce TAKE_PTR() macro 58987f02cb systemd
 */
#define TAKE_PTR(ptr)                           \
        ({                                      \
                typeof(ptr) _ptr_ = (ptr);      \
                (ptr) = NULL;                   \
                _ptr_;                          \
        })

size_t strv_length(char * const *l);
int readlinkat_malloc(int fd, const char *p, char **ret);
int readlink_malloc(const char *p, char **ret);
int readlink_value(const char *p, char **ret);
int read_process_env(const char *path, char **ret);
int read_task_ns_id(const char *path, unsigned long flag, unsigned int *ret_i);
int read_task_mnt_id(const char *path, struct stat *st);
int pin_init_task_ns(int fd);

int is_lsmbpf_supported();

#endif /* __BPFLOCK_UTILS_H */
