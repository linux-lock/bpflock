// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
 * Implements Fileless execution restrictions.
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
#include "filelesslock.h"
#include "filelesslock.skel.h"

static struct options {
        int perm_int;
        char *perm;
        char *maps_filter_str;
        unsigned long filter_int;
        bool debug;
} opt = {};

const char *argp_program_version = "filelesslock 0.1";
const char *argp_program_bug_address =
        "https://github.com/linux-lock/bpflock";
const char argp_program_doc[] =
"bpflock filelesslock - restrict fileless binary execution from memory.\n"
"\n"
"USAGE: filelesslock [--help] [-p PROFILE] [--maps-filter=MAP]\n"
"\n"
"EXAMPLES:\n"
"  # Allow profile: fileless binary execution from memory is\n"
"  # allowed. Default profile.\n"
"  filelesslock\n"
"  filelesslock --profile=allow\n\n"
"  # Baseline profile: fileless binary execution from memory is\n"
"  # restricted to privileged tasks in pid and network namespaces.\n"
"  filelesslock --profile=baseline\n\n"
"  # Restricted profile: deny fileless binary execution for all.\n"
"  filelesslock --profile=restricted\n";

static const struct argp_option opts[] = {
        { "profile", 'p', "PROFILE", 0, "Profile to apply, one of the following: allow, baseline or restricted. Default value is: allow." },
        { "maps-filter", 'm', "cgroupmap,pidnsmap,netnsmap", 0, "Baseline map filter to allow tasks that are in these maps to perform fileless execution."},
        { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
        {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'h':
                argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

/* Setup bpf map options */
static int setup_bpf_args_map(struct filelesslock_bpf *skel)
{
        uint32_t key = FILELESSLOCK_PROFILE;
        int f;

        opt.perm_int = 0;

        f = bpf_map__fd(skel->maps.filelesslock_args_map);
        if (f < 0) {
                fprintf(stderr, "%s: error: failed to get bpf map fd: %d\n",
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

        bpf_map_update_elem(f, &key, &opt.perm_int, BPF_ANY);

        return 0;
}

int main(int argc, char **argv)
{
        static const struct argp argp = {
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

        struct filelesslock_bpf *skel = NULL;
        struct bpf_program *prog = NULL;
        struct bpf_object *obj = NULL;
        struct stat st;
        char *buf = NULL;
        int err;
        int i;

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

        err = stat(fileless_security_map.pin_path, &st);
        if (err == 0) {
                fprintf(stdout, "%s: %s already loaded nothing todo, please delete pinned directory '%s' "
                        "to be able to run it again.\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK, fileless_security_map.pin_path);
                return -EALREADY;
        }

        buf = malloc(128);
        if (!buf) {
                fprintf(stderr, "%s: error: failed to allocate memory\n",
                        LOG_BPFLOCK);
                return -ENOMEM;
        }

        memset(buf, 0, 128);

        skel = filelesslock_bpf__open();
        if (!skel) {
                fprintf(stderr, "%s: %s: error: failed to open BPF skelect\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK);
                err = -EINVAL;
                goto cleanup;
        }

        obj = bpf_object__open_mem(skel->skeleton->data, skel->skeleton->data_sz, NULL);
        if (!obj) {
                fprintf(stderr, "%s: %s: error: failed to open bpf mem\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK);
                err = libbpf_get_error(link);
                goto cleanup;
        }

        err = bpf_reuse_shared_maps(obj);
        if (err < 0) {
                fprintf(stderr, "%s: %s: failed to reuse shared bpf maps: %d\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK, err);
        }

        err = filelesslock_bpf__load(skel);
        if (err) {
                fprintf(stderr, "%s: %s: error: failed to load BPF skelect: %d\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK, err);
                goto cleanup;
        }

        err = setup_bpf_args_map(skel);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to setup bpf opt map: %d\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK, err);
                goto cleanup;
        }

        err = push_host_init_ns(skel->maps.bpflock_pidnsmap);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to setup bpf shared maps: %d\n",
                        LOG_BPFLOCK, LOG_FILELESSLOCK, err);
                goto cleanup;
        }

        mkdir(BPFLOCK_PIN_PATH, 0700);
        mkdir(fileless_security_map.pin_path, 0700);

        err = bpflock_bpf_object__pin(skel->obj, fileless_security_map.pin_path);
        if (err) {
                libbpf_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "%s: %s: error: failed to pin bpf obj into '%s'\n",
			LOG_BPFLOCK, LOG_FILELESSLOCK, buf);
                goto cleanup;
        }

        i = 0;
        bpf_object__for_each_program(prog, skel->obj) {
                struct bpf_link *link = bpf_program__attach(prog);
                err = libbpf_get_error(link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: %s: error: failed to attach BPF programs: %s\n",
                                LOG_BPFLOCK, LOG_FILELESSLOCK, strerror(-err));
                        goto cleanup;
                }

                err = bpf_link__pin(link, fileless_prog_links[i].link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: %s: error: failed to pin bpf obj into '%s'\n",
                                LOG_BPFLOCK, LOG_FILELESSLOCK, buf);
                        goto cleanup;
                }
                i++;
        }

        if (opt.perm_int == BPFLOCK_P_RESTRICTED) {
                printf("%s: success: profile: restricted - fileless execution is now disabled - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, fileless_security_map.pin_path);
        } else if (opt.perm_int == BPFLOCK_P_BASELINE) {
                printf("%s: success: profile: baseline - fileless execution is now restricted only to initial namespaces - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, fileless_security_map.pin_path);
        } else {
                printf("%s: success: profile: allow - fileless execution is allowed - delete pinned file '%s' to disable access logging.\n",
                        LOG_BPFLOCK, fileless_security_map.pin_path);
        }

cleanup:
        filelesslock_bpf__destroy(skel);
        free(buf);

        return err;
}
