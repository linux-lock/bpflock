// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
 * Implements access BPF access restrictions.
 */

#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "trace_helpers.h"
#include "bpflock_utils.h"
#include "disablebpf.h"
#include "disablebpf.skel.h"

static struct options {
        int perm_int;
        int block_op_int;
        char *perm;
        char *block_op;
} opt = {};

const char *argp_program_version = "disablebpf 0.1";
const char *argp_program_bug_address =
        "https://github.com/linux-lock/bpflock";
const char argp_program_doc[] =
"bpflock disablebpf - restrict access to BPF system call.\n"
"\n"
"USAGE: disablebpf [--help] [-p PERM] [-b CMD]\n"
"\n"
"EXAMPLES:\n"
"  # BPF is allowed.\n"
"  disablebpf -p allow\n\n"
"  # Restrict BPF system call to tasks in initial mnt namespace.\n"
"  disablebpf\n"
"  disablebpf -p restrict\n\n"
"  # Restrict BPF to tasks in initial mnt namespace and\n"
"  # block the BPF load program command.\n"
"  disablebpf -p restrict -b prog_load\n\n"
"  # Deny BPF system call for all.\n"
"  disablebpf -p deny\n";

static const struct argp_option opts[] = {
        { "permission", 'p', "PERM", 0, "Permission to apply, one of the following: allow, restrict or deny. Default value is: restrict." },
        { "block", 'b', "CMD", 0, "Block BPF commands, possible values: 'map_create, prog_load, btf_load, bpf_write' " },
        { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
        {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'h':
                argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
                break;
        case 'b':
                if (strlen(arg) + 1 > 128) {
                        fprintf(stderr, "invaild -b|--block argument: too long\n");
                        argp_usage(state);
                }
                opt.block_op = strndup(arg, strlen(arg));
                break;
        case 'p':
                if (strlen(arg) + 1 > 64) {
                        fprintf(stderr, "invaild -p|--permission argument: too long\n");
                        argp_usage(state);
                }
                opt.perm = strndup(arg, strlen(arg));
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }

        return 0;
}

/* Setup bpf map options */
static int setup_bpf_opt_map(struct disablebpf_bpf *skel, int *fd)
{
        uint32_t perm_k = BPFLOCK_BPF_PERM;
        uint32_t op_k = BPFLOCK_BPF_OP;
        int f;

        opt.perm_int = 0;
        opt.block_op_int = 0;

        f = bpf_map__fd(skel->maps.disablebpf_map);
        if (f < 0) {
                fprintf(stderr, "%s: error: failed to get bpf map fd: %d\n",
                        LOG_BPFLOCK, f);
                return f;
        }

        if (!opt.perm) {
                opt.perm_int = BPFLOCK_BPF_RESTRICT;
        } else {
                if (strncmp(opt.perm, "deny", 4) == 0) {
                        opt.perm_int = BPFLOCK_BPF_DENY;
                } else if (strncmp(opt.perm, "restrict", 8) == 0) {
                        opt.perm_int = BPFLOCK_BPF_RESTRICT;
                } else if (strncmp(opt.perm, "allow", 5) == 0 ||
                           strncmp(opt.perm, "none", 4) == 0) {
                        opt.perm_int = BPFLOCK_BPF_ALLOW;
                }
        }

        if (opt.block_op) {
                if (strstr(opt.block_op, "map_create") != NULL)
                        opt.block_op_int |= BPFLOCK_MAP_CREATE;
                if (strstr(opt.block_op, "prog_load") != NULL)
                        opt.block_op_int |= BPFLOCK_PROG_LOAD;
                if (strstr(opt.block_op, "btf_load") != NULL)
                        opt.block_op_int |= BPFLOCK_BTF_LOAD;
                if (strstr(opt.block_op, "bpf_write") != NULL)
                        opt.block_op_int |= BPFLOCK_BPF_WRITE;
        }

        *fd = f;

        bpf_map_update_elem(f, &perm_k, &opt.perm_int, BPF_ANY);
        if (opt.block_op_int > 0)
                bpf_map_update_elem(f, &op_k, &opt.block_op_int, BPF_ANY);

        return 0;
}

/* Returns valid fd if it can reuses ns_map */
int reuse_ns_map(struct disablebpf_bpf *skel, int *fd)
{
        struct stat st;
        struct bpf_map *ns_map;
        int err;

        err = stat(BPFLOCK_NS_MAP_PIN, &st);
        if (err < 0)
                return 0;

        ns_map = bpf_object__find_map_by_name(skel->obj, "ns_map");
        if (!ns_map)
                return 0;

        return 0;
}

static int setup_bpf_env_map(struct disablebpf_bpf *skel, int *fd)
{
        int err;
        int f;

        if (*fd > 0)
                return 0;

        f = bpf_map__fd(skel->maps.disablebpf_ns_map);
        if (f < 0) {
                fprintf(stderr, "%s: error: failed to get ns map fd: %d\n",
                        LOG_BPFLOCK, f);
                return f;
        }

        err = pin_init_task_ns(f);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to pin init task namespace: %d\n",
                        LOG_BPFLOCK, err);
                return err;
        }

        *fd = f;

        return err;
}

int main(int argc, char **argv)
{
        static const struct argp argp = {
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

        struct disablebpf_bpf *skel = NULL;
        struct bpf_link *link = NULL;
        struct bpf_program *prog = NULL;
        int disablebpf_map_fd = -1, ns_map_fd = -1;
        struct stat st;
        char *buf = NULL;
        int err, i;

        err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
        if (err)
                return err;

        err = is_lsmbpf_supported();
        if (err) {
                fprintf(stderr, "%s: error: failed to check LSM BPF support\n",
                        LOG_BPFLOCK);
                return err;
        }

        err = bump_memlock_rlimit();
        if (err) {
                fprintf(stderr, "%s: error: failed to increase rlimit: %s\n",
                        LOG_BPFLOCK, strerror(errno));
                return err;
        }

        err = stat(bpf_security_map.pin_path, &st);
        if (err == 0) {
                fprintf(stdout, "%s: %s already loaded nothing todo, please delete pinned directory '%s' "
                        "to be able to run it again.\n",
                        LOG_BPFLOCK, argv[0], bpf_security_map.pin_path);
                return -EALREADY;
        }

        buf = malloc(128);
        if (!buf) {
                fprintf(stderr, "%s: error: failed to allocate memory\n",
                        LOG_BPFLOCK);
                return -ENOMEM;
        }

        memset(buf, 0, 128);

        skel = disablebpf_bpf__open();
        if (!skel) {
                fprintf(stderr, "%s: error: failed to open BPF skelect\n",
                        LOG_BPFLOCK);
                err = -EINVAL;
                goto cleanup;
        }

        err = disablebpf_bpf__load(skel);
        if (err) {
                fprintf(stderr, "%s: error: failed to load BPF skelect: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        err = setup_bpf_opt_map(skel, &disablebpf_map_fd);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf opt map: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        err = setup_bpf_env_map(skel, &ns_map_fd);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf env map: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        mkdir(BPFLOCK_PIN_PATH, 0700);
        mkdir(bpf_security_map.pin_path, 0700);

        err = bpf_object__pin(skel->obj, bpf_security_map.pin_path);
        if (err) {
                libbpf_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "%s: error: failed to pin bpf obj into '%s'\n",
			LOG_BPFLOCK, buf);
                goto cleanup;
        }

        i = 0;
        bpf_object__for_each_program(prog, skel->obj) {
                link = bpf_program__attach(prog);
                err = libbpf_get_error(link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: error: failed to attach BPF programs: %s\n",
                                LOG_BPFLOCK, strerror(-err));
                        goto cleanup;
                }

                err = bpf_link__pin(link, bpf_prog_links[i].link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: error: failed to pin bpf obj into '%s'\n",
                                LOG_BPFLOCK, buf);
                        goto cleanup;
                }
                i++;
        }

        if (opt.perm_int == BPFLOCK_BPF_DENY) {
                printf("%s: success: The bpf() syscall is now disabled - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, bpf_security_map.pin_path);
        } else if (opt.perm_int == BPFLOCK_BPF_RESTRICT) {
                printf("%s: success: The bpf() syscall is now restricted only to initial mnt namespace - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, bpf_security_map.pin_path);
        } else {
                printf("%s: The bpf() syscall is allowed - pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, bpf_security_map.pin_path);
        }

cleanup:
        if (link)
                bpf_link__destroy(link);

        if (skel)
                disablebpf_bpf__destroy(skel);

        free(buf);

        return err != 0;
}
