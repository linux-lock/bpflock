// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
 * Implements BPF access restrictions.
 */

#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bpflock_shared_defs.h"
#include "trace_helpers.h"
#include "bpflock_utils.h"
#include "bpfrestrict.h"
#include "bpfrestrict.skel.h"

static struct options {
        int perm_int;
        int block_op_int;
        char *perm;
        char *block_op;
        char *maps_filter_str;
        unsigned long filter_int;
        bool debug;
} opt = {};

const char *argp_program_version = "bpfrestrict 0.1";
const char *argp_program_bug_address =
        "https://github.com/linux-lock/bpflock";
const char argp_program_doc[] =
"bpflock bpfrestrict - restrict access to BPF system call.\n"
"\n"
"USAGE: bpfrestrict [--help] [--debug] [--profile=PROFILE] [--maps-filter=MAP] [--block=CMDs]\n"
"\n"
"EXAMPLES:\n"
"  # Global allow profile: BPF is allowed.\n"
"  bpfrestrict\n"
"  bpfrestrict --profile=allow\n\n"
"  # Global baseline profile: restrict BPF system call to the tasks that\n"
"  # satisfy the baseline filter. The default baseline filter is pidnsmap\n"
"  # that includes the initial pid namespace.\n"
"  bpfrestrict --profile=baseline\n\n"
"  # Global baseline profile: restrict BPF to the tasks that satisfy the\n"
"  # baseline filter and block the BPF load program command.\n"
"  bpfrestrict --profile=baseline --block=prog_load\n\n"
"  # Global baseline profile with default pidnsmap: restrict BPF to the\n"
"  # tasks that are in the pidnsmap, and block other tasks. By default\n"
"  # initial pid namespace is allowed.\n"
"  bpfrestrict --profile=baseline\n"
"  bpfrestrict --profile=baseline --maps-filter=pidnsmap\n\n"
"  # Global baseline profile with cgroupmap and pidnsmap: restrict BPF to\n"
"  # tasks that are in the pidnsmap and cgroupmap, and block all other\n"
"  # tasks. By default initial pid namespace is allowed.\n"
"  bpfrestrict --profile=baseline --maps-filter=pidnsmap,cgroupmap\n\n"
"  # Global restricted profile: deny BPF system call for all.\n"
"  bpfrestrict --profile=restricted\n";

static const struct argp_option opts[] = {
        { "profile", 'p', "PROFILE", 0, "Profile to apply, one of the following: allow, baseline or restricted. Default value is: allow." },
        { "block", 'b', "CMD", 0, "Block BPF commands, possible values: 'map_create, prog_load, btf_load, bpf_write' " },
        { "maps-filter", 'm', "cgroupmap,pidnsmap,netnsmap", 0, "Baseline map filter to allow tasks that are in these maps to perform BPF operations."},
        { "debug", 'd', NULL, 0, "Send debug output to '/sys/kernel/debug/tracing/trace_pipe'" },
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
        case 'd':
                opt.debug = true;
                break;
        case 'p':
                if (strlen(arg) + 1 > 64) {
                        fprintf(stderr, "invaild -p|--profile argument: too long\n");
                        argp_usage(state);
                }
                opt.perm = strndup(arg, strlen(arg));
                break;
        case 'm':
                if (strlen(arg) + 1 > 128) {
                        fprintf(stderr, "invaild -m|--maps-filter argument: too long\n");
                        argp_usage(state);
                }
                opt.maps_filter_str = strndup(arg, strlen(arg));
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }

        return 0;
}

static int pre_setup_bpf_args_map(struct bpfrestrict_bpf *skel)
{
        if (!opt.debug)
                return 0;

        skel->rodata->debug = true;

        return 0;
}

/* Setup bpfrestrict_args_map */
static int setup_bpf_args_map(struct bpfrestrict_bpf *skel)
{
        uint32_t key = BPFRESTRICT_PROFILE, val = 0;
        int f;

        opt.perm_int = 0;
        opt.block_op_int = 0;
        opt.filter_int = 0;

        f = bpf_map__fd(skel->maps.bpfrestrict_args_map);
        if (f < 0) {
                fprintf(stderr, "%s: error: failed to get bpfrestrict_args_map fd: %d\n",
                        LOG_BPFLOCK, f);
                return f;
        }

        if (!opt.perm) {
                opt.perm_int = BPFLOCK_P_ALLOW;
        } else {
                if (strncmp(opt.perm, "restricted", 10) == 0) {
                        opt.perm_int = BPFLOCK_P_RESTRICTED;
                } else if (strncmp(opt.perm, "baseline", 8) == 0) {
                        opt.perm_int = BPFLOCK_P_BASELINE;
                } else if (strncmp(opt.perm, "allow", 5) == 0 ||
                           strncmp(opt.perm, "none", 4) == 0 ||
                           strncmp(opt.perm, "privileged", 10)) {
                        opt.perm_int = BPFLOCK_P_ALLOW;
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

        bpf_map_update_elem(f, &key, &opt.perm_int, BPF_ANY);
        if (opt.block_op_int > 0) {
                key = BPFRESTRICT_BLOCK_OP;
                bpf_map_update_elem(f, &key, &opt.block_op_int, BPF_ANY);
        }

        if (opt.maps_filter_str) {
                if (strstr(opt.maps_filter_str, "pidnsmap") != NULL)
                        opt.filter_int |= BPFLOCK_P_FILTER_PIDNS;
                if (strstr(opt.maps_filter_str, "netnsmap") != NULL)
                        opt.filter_int |= BPFLOCK_P_FILTER_NETNS;
                if (strstr(opt.maps_filter_str, "cgroupmap") != NULL)
                        opt.filter_int |= BPFLOCK_P_FILTER_CGROUP;

                if (!opt.filter_int) {
                        fprintf(stderr, "%s: error: failed to parse --maps-filter invalid value.\n",
                               LOG_BPFLOCK);
                        return -EINVAL;
                }
        } else {
                opt.filter_int |= BPFLOCK_P_FILTER_PIDNS;
        }

        key = BPFRESTRICT_MAPS_FILTER;
        bpf_map_update_elem(f, &key, &opt.filter_int, BPF_ANY);

        key = BPFRESTRICT_DEBUG;
        val = opt.debug ? 1 : 0;
        bpf_map_update_elem(f, &key, &val, BPF_ANY);

        return 0;
}

int main(int argc, char **argv)
{
        static const struct argp argp = {
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

        struct bpfrestrict_bpf *skel = NULL;
        struct bpf_program *prog = NULL;
        struct bpf_object *obj = NULL;
        char *buf = NULL;
        struct stat st;
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
                        LOG_BPFLOCK, LOG_BPFRESTRICT, bpf_security_map.pin_path);
                return -EALREADY;
        }

        buf = malloc(128);
        if (!buf) {
                fprintf(stderr, "%s: error: failed to allocate memory\n",
                        LOG_BPFLOCK);
                return -ENOMEM;
        }

        memset(buf, 0, 128);

        skel = bpfrestrict_bpf__open();
        if (!skel) {
                fprintf(stderr, "%s: %s: error: failed to open BPF skelect\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT);
                err = -EINVAL;
                goto cleanup;
        }

        obj = bpf_object__open_mem(skel->skeleton->data, skel->skeleton->data_sz, NULL);
        if (!obj) {
                fprintf(stderr, "%s: %s: error: failed to open bpf mem\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT);
                err = libbpf_get_error(link);
                goto cleanup;
        }

        err = bpf_reuse_shared_maps(obj);
        if (err < 0) {
                fprintf(stderr, "%s: %s: failed to reuse shared bpf maps: %d\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, err);
        }

        pre_setup_bpf_args_map(skel);

        err = bpfrestrict_bpf__load(skel);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to load BPF skelect: %d\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, err);
                goto cleanup;
        }

        err = setup_bpf_args_map(skel);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to setup bpf args map: %d\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, err);
                goto cleanup;
        }

        err = push_host_init_ns(skel->maps.bpflock_pidnsmap);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to setup bpf shared maps: %d\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, err);
                goto cleanup;
        }

        mkdir(BPFLOCK_PIN_PATH, 0700);
        mkdir(bpf_security_map.pin_path, 0700);

        err = bpflock_bpf_object__pin(skel->obj, bpf_security_map.pin_path);
        if (err < 0) {
                libbpf_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "%s: %s: error: failed to pin bpf obj into '%s': %s\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, bpf_security_map.pin_path, buf);
                goto cleanup;
        }

        i = 0;
        bpf_object__for_each_program(prog, skel->obj) {
                struct bpf_link *link = bpf_program__attach(prog);
                err = libbpf_get_error(link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: %s: error: failed to attach BPF programs: %s\n",
                                LOG_BPFLOCK, LOG_BPFRESTRICT, strerror(-err));
                        goto cleanup;
                }

                err = bpf_link__pin(link, bpf_prog_links[i].link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: %s: error: failed to pin bpf obj into '%s'\n",
                                LOG_BPFLOCK, LOG_BPFRESTRICT, buf);
                        goto cleanup;
                }
                i++;
        }

        if (opt.perm_int == BPFLOCK_P_RESTRICTED) {
                printf("%s: %s: success: profile: restricted - the bpf() syscall is now disabled - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, bpf_security_map.pin_path);
        } else if (opt.perm_int == BPFLOCK_P_BASELINE) {
                printf("%s: %s: success: profile: baseline - the bpf() syscall is restricted only to initial namespaces - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, bpf_security_map.pin_path);
        } else {
                printf("%s: %s: success: profile: allow - the bpf() syscall is allowed - delete pinned file '%s' to disable access logging.\n",
                        LOG_BPFLOCK, LOG_BPFRESTRICT, bpf_security_map.pin_path);
        }

cleanup:
        bpfrestrict_bpf__destroy(skel);
        free(buf);

        return err;
}
