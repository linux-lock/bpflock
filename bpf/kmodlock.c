/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 *
 * Implements access restrictions on module loading and unloading operations.
 */

#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bpflock_security_class.h"
#include "bpflock_shared_defs.h"
#include "trace_helpers.h"
#include "bpflock_utils.h"
#include "kmodlock.h"
#include "kmodlock.skel.h"

static struct options {
        int perm_int;
        int block_op_int;
        char *perm;
        char *block_op;
} opt = {};

const char *argp_program_version = "kmodlock 0.1";
const char *argp_program_bug_address =
        "https://github.com/linux-lock/bpflock";
const char argp_program_doc[] =
"bpflock kmodlock - restrict kernel module load operations.\n"
"\n"
"USAGE: kmodlock [--help] [-p PROFILE] [-b CMD] [--rootfs] [--ro] [--ro-dev]\n"
"\n"
"EXAMPLES:\n"
"  # Allow profile: kernel module operations are allowed.\n"
"  kmodlock --profile=allow\n\n"
"  # Baseline profile: kernel module operations are allowed for tasks in initial pid namespace.\n"
"  kmodlock --profile=baseline\n\n"
"  # Baseline profile: restrict kernel module operations to tasks in initial pid namespace and\n"
"  # block loading of unsigned modules and other automatic module operations.\n"
"  kmodlock --profile=baseline --block=autoload_module,unsigned_module\n\n"
"  # Restricted profile: deny loading kernel modules for all.\n"
"  kmodlock ---profile=restricted\n";

static const struct argp_option opts[] = {
        { "profile", 'p', "PROFILE", 0, "Profile to apply, one of the following: allow, baseline or restricted. Default value is: allow." },
        { "block", 'b', "CMD", 0, "Block module operations, possible values: 'load_module, unload_module, autoload_module, unsigned_module, unsafe_module_parameters' " },
        { "rootfs", 'f', NULL, 0, "Allow module operations only if the modules originate from the root filesystem."},
        { "ro", 'r', NULL, 0, "Allow module operations only if the root filesystem is mounted read-only"},
        { "ro-dev", 'd', NULL, 0, "Allow module operations only if the filesystem is backed by a read-only device."},
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
                        fprintf(stderr, "invaild -p|--profile argument: too long\n");
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
static int setup_km_opt_map(struct kmodlock_bpf *skel, int *fd)
{
        uint32_t perm_k = BPFLOCK_KM_PERM;
        uint32_t op_k = BPFLOCK_KM_OP;
        int f;

        opt.perm_int = 0;
        opt.block_op_int = 0;

        f = bpf_map__fd(skel->maps.disablemods_map);
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

        if (opt.block_op) {
                if (strstr(opt.block_op, "load_module") != NULL)
                        opt.block_op_int |= BPFLOCK_KM_LOAD;
                if (strstr(opt.block_op, "unload_module") != NULL)
                        opt.block_op_int |= BPFLOCK_KM_UNLOAD;
                if (strstr(opt.block_op, "autoload_module") != NULL)
                        opt.block_op_int |= BPFLOCK_KM_AUTOLOAD;
                if (strstr(opt.block_op, "unsigned_module") != NULL)
                        opt.block_op_int |= BPFLOCK_KM_UNSIGNED;
                if (strstr(opt.block_op, "unsafe_module_prameters") != NULL)
                        opt.block_op_int |= BPFLOCK_KM_UNSAFEMOD;
        }

        *fd = f;

        bpf_map_update_elem(f, &perm_k, &opt.perm_int, BPF_ANY);
        if (opt.block_op_int > 0)
                bpf_map_update_elem(f, &op_k, &opt.block_op_int, BPF_ANY);

        return 0;
}

static int setup_km_env_map(struct kmodlock_bpf *skel, int *fd)
{
        int err;
        int f;

        if (*fd > 0)
                return 0;

        f = bpf_map__fd(skel->maps.disablemods_ns_map);
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

static int setup_km_env_sbroot(struct kmodlock_bpf *skel, int *fd)
{
        struct bl_stat lstat;
        struct stat st;
        int ret, k = BPFLOCK_KM_SB;

        if (*fd <= 0) 
                return -EINVAL;

        ret = stat_sb_root(&st);
        if (ret < 0)
                return ret;

        lstat.st_dev = st.st_dev;

        bpf_map_update_elem(*fd, &k, &lstat, BPF_ANY);

        return 0;
}

int main(int argc, char **argv)
{
        static const struct argp argp = {
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

        struct kmodlock_bpf *skel = NULL;
        struct bpf_link *link = NULL;
        struct bpf_program *prog = NULL;
        int kmodlock_map_fd = -1, ns_map_fd = -1;
        struct stat st;
        char *buf = NULL;
        int err, i, buflen = 512;

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

        err = stat(dmodules_security_map.pin_path, &st);
        if (err == 0) {
                fprintf(stdout, "%s: %s already loaded nothing todo, please delete pinned file '%s' "
                        "to be able to run it again.\n",
                        LOG_BPFLOCK, argv[0], dmodules_security_map.pin_path);
                return -EALREADY;
        }

        buf = malloc(buflen);
        if (!buf) {
                fprintf(stderr, "%s: error: failed to allocate memory\n",
                        LOG_BPFLOCK);
                return -ENOMEM;
        }

        memset(buf, 0, buflen);

        skel = kmodlock_bpf__open();
        if (!skel) {
                fprintf(stderr, "%s: error: failed to open BPF skelect\n",
                        LOG_BPFLOCK);
                err = -EINVAL;
                goto cleanup;
        }

        err = kmodlock_bpf__load(skel);
        if (err) {
                fprintf(stderr, "%s: error: failed to load BPF skelect: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        err = setup_km_opt_map(skel, &kmodlock_map_fd);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf opt map: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        err = setup_km_env_map(skel, &ns_map_fd);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf env map: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        err = setup_km_env_sbroot(skel, &ns_map_fd);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf super block env: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        mkdir(BPFLOCK_PIN_PATH, 0700);
        mkdir(dmodules_security_map.pin_path, 0700);

        err = bpf_object__pin(skel->obj, dmodules_security_map.pin_path);
        if (err) {
                libbpf_strerror(err, buf, buflen);
                fprintf(stderr, "%s: %s: error: failed to pin obj into link '%s': %s\n",
			LOG_BPFLOCK, LOG_KMODLOCK, dmodules_security_map.pin_path, buf);
                goto cleanup;
        }

        i = 0;
        bpf_object__for_each_program(prog, skel->obj) {
                if (i >= sizeof(dmodules_prog_links) / sizeof(bpflock_class_prog_link_t))
                        break;

                link = bpf_program__attach(prog);
                err = libbpf_get_error(link);
                if (err) {
                        libbpf_strerror(err, buf, buflen);
                        fprintf(stderr, "%s: %s: error: failed to attach BPF programs: %s\n",
                                LOG_BPFLOCK, LOG_KMODLOCK, strerror(-err));
                        goto cleanup;
                }

                err = bpf_link__pin(link, dmodules_prog_links[i].link);
                if (err) {
                        libbpf_strerror(err, buf, buflen);
                        fprintf(stderr, "%s: %s: error: failed to pin bpf obj into link '%s': %s\n",
                                LOG_BPFLOCK, LOG_KMODLOCK, dmodules_prog_links[i].link, buf);
                        goto cleanup;
                }

                i++;
        }

        if (opt.perm_int == BPFLOCK_P_RESTRICTED) {
                printf("%s: success: profile: restricted - kernel module load operations are now disabled - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, dmodules_security_map.pin_path);
        } else if (opt.perm_int == BPFLOCK_P_BASELINE) {
                printf("%s: success: profile: baseline - kernel module load operations are now restricted only to initial pid namespace - delete pinned file '%s' to re-enable\n",
                        LOG_BPFLOCK, dmodules_security_map.pin_path);
        } else {
                printf("%s: success: profile : allow - kernel module load operations are allowed - delete pinned file '%s' to disable access logging\n",
                        LOG_BPFLOCK, dmodules_security_map.pin_path);
        }

cleanup:
        if (link)
                bpf_link__destroy(link);

        if (skel)
                kmodlock_bpf__destroy(skel);

        free(buf);

        return err != 0;
}
