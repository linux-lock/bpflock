/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
 * Implements access restrictions on bpf syscall, it supports following values:
 *   Per running context:
 *	- allow: bpf is allowed.
 *	- restrict: bpf is allowed only from processes that are in the initial mount
 *           namespace.
 *	- deny: deny bpf syscall and all its commands for all processes.
 *           Make sure to execute this program last during boot and after
 *           all necessary bpf programs have been loaded. For containers workload
 *           delete the pinned file and load it again after container initialization.
 *
 *   If bpf is allowed, then tasks can be restricted to the following commands: 
 *   - map_create: allow creation of bpf maps.
 *   - btf_load: allow loading BPF Type Format (BTF) metadata into the kernel.
 *   - prog_load: allow loading bpf programs.
 *   All other commands are allowed.
 *
 * To disable this program, delete the pinned file "/sys/fs/bpf/bpflock/disable-bpf",
 * re-executing will enable it again.
 */

#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "trace_helpers.h"
#include "bpflock_utils.h"
#include "disablebpf.h"
#include "disablebpf.skel.h"

static struct options {
        char *perm;
        int perm_int;
        char *allow_op;
        int allow_op_int;
} opt = {};

const char *argp_program_version = "disablebpf 0.1";
const char *argp_program_bug_address =
        "https://github.com/linux-lock/bpflock";
const char argp_program_doc[] =
"bpflock disablebpf - restrict access to BPF system call.\n"
"\n"
"USAGE: disablebpf [--help] [-p PERM] [-c CMD]\n"
"\n"
"EXAMPLES:\n"
"    # Restrict BPF system call to tasks in init mnt namespace.\n"
"    disablebpf\n"
"    disablebpf -p restrict\n"
"\n    # BPF is allowed.\n"
"    disablebpf -p allow\n"
"\n    # Allow BPF load program command if task is in init mnt namespace.\n"
"    disablebpf -p restrict -c prog_load\n"
"\n    # Deny BPF system call for all.\n"
"    disablebpf -p deny\n";

static const struct argp_option opts[] = {
        { "permission", 'p', "PERM", 0, "Permission to apply, one of the following values: allow, restrict or deny. Default value is: restrict." },
        { "command", 'c', "CMD", 0, "Allowed BPF commands, possible values: 'map_create, prog_load, btf_load' " },
        { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
        {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'h':
                argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
                break;
        case 'c':
                if (strlen(arg) + 1 > 64) {
                        fprintf(stderr, "invaild -a|--allow argument: too long\n");
                        argp_usage(state);
                }
                opt.allow_op = arg;
                break;
        case 'p':
                if (strlen(arg) + 1 > 64) {
                        fprintf(stderr, "invaild -p|--permission argument: too long\n");
                        argp_usage(state);
                }
                opt.perm = arg;
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }

        return 0;
}

/* Setup bpf map options */
static int setup_bpf_opt_map(int fd, struct options *opt)
{
        uint32_t perm_k = BPFLOCK_BPF_PERM;
        uint32_t op_k = BPFLOCK_BPF_OP;

        opt->perm_int = 0;
        opt->allow_op_int = 0;

        if (fd <= 0)
                return -EINVAL;

        if (!opt->perm)
                opt->perm_int = BPFLOCK_BPF_RESTRICT;
        else {
                if (strneq(opt->perm, "deny", 4) == 0)
                        opt->perm_int = BPFLOCK_BPF_DENY;
                else if (strneq(opt->perm, "restrict", 8) == 0) {
                        opt->perm_int = BPFLOCK_BPF_RESTRICT;
                        if (strstr(opt->allow_op, "map_create") != NULL)
                                opt->allow_op_int &= BPFLOCK_MAP_CREATE;
                        if (strstr(opt->allow_op, "prog_load") != NULL)
                                opt->allow_op_int &= BPFLOCK_PROG_LOAD;
                        if (strstr(opt->allow_op, "btf_load") != NULL)
                                opt->allow_op_int &= BPFLOCK_BTF_LOAD;
                } else if (strneq(opt->perm, "allow", 5) == 0 ||
                           strneq(opt->perm, "none", 4) == 0)
                        opt->perm_int = BPFLOCK_BPF_ALLOW;
        }

        bpf_map_update_elem(fd, &perm_k, &opt->perm_int, BPF_ANY);
        if (opt->allow_op_int > 0)
                bpf_map_update_elem(fd, &op_k, &opt->allow_op_int, BPF_ANY);

        return 0;
}

static int setup_bpf_env_map(int fd, struct options *opt)
{
        char *value;
        int ret;
        /* Read mnt namespace */

        ret = read_process_env("/proc/1/ns/mnt", &value);
        if (ret < 0)
                return ret;

        free(value);
        return 0;
}

int main(int argc, char **argv)
{
        static const struct argp argp = {
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

        struct disablebpf_bpf *skel;
        struct bpf_link *link = NULL;
        struct bpf_program *prog;
        char buf[100];
        int err, disablebpf_map_fd, env_map_fd;

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
                return 1;
        }

        skel = disablebpf_bpf__open();
        if (!skel) {
                fprintf(stderr, "%s: error: failed to open BPF skelect\n",
                        LOG_BPFLOCK);
                return 1;
        }

        err = disablebpf_bpf__load(skel);
        if (err) {
                fprintf(stderr, "%s: error: failed to load BPF skelect: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        disablebpf_map_fd = bpf_map__fd(skel->maps.disablebpf_map);
        if (disablebpf_map_fd < 0) {
                fprintf(stderr, "%s: error: failed to get bpf map fd: %d\n",
                        LOG_BPFLOCK, disablebpf_map_fd);
                err = disablebpf_map_fd;
                goto cleanup;
        }


        env_map_fd = bpf_map__fd(skel->maps.disablebpf_env_map);
        if (env_map_fd < 0) {
                fprintf(stderr, "%s: error: failed to get bpf map fd: %d\n",
                        LOG_BPFLOCK, env_map_fd);
                err = env_map_fd;
                goto cleanup;
        }

        err = setup_bpf_opt_map(disablebpf_map_fd, &opt);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf opt map: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        err = setup_bpf_env_map(env_map_fd, &opt);
        if (err < 0) {
                fprintf(stderr, "%s: error: failed to setup bpf env map: %d\n",
                        LOG_BPFLOCK, err);
                goto cleanup;
        }

        prog = bpf_program__next(NULL, skel->obj);
        if (!prog) {
                fprintf(stderr, "%s: error: failed to find LSM disable bpf program!\n",
                        LOG_BPFLOCK);
                err = -ENOENT;
                goto cleanup;
        }

        link = bpf_program__attach(prog);
        err = libbpf_get_error(link);
        if (err) {
                libbpf_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "%s: error: failed to attach BPF programs: %s\n",
                        LOG_BPFLOCK, strerror(-err));
                goto cleanup;
        }

        err = bpf_link__pin(link, bpf_security_map.pin_path);
        if (err) {
                libbpf_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "%s: error: failed to pin '%s'\n", LOG_BPFLOCK, buf);
                goto cleanup;
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
        bpf_link__destroy(link);
        //bpf_link__destroy(link);
        disablebpf_bpf__destroy(skel);

        return err != 0;
}
