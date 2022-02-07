/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Djalal Harouni
 */

/*
 * Implements access on kernel image.
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
#include "kimglock.h"
#include "kimglock.skel.h"

static struct options {
        int perm_int;
        int block_op_int;
        char *perm;
        char *block_op;
        char *maps_filter_str;
        unsigned long filter_int;
        bool debug;
} opt = {};

const char *argp_program_version = "kimglock 0.1";
const char *argp_program_bug_address =
        "https://github.com/linux-lock/bpflock";
const char argp_program_doc[] =
"bpflock kimglock - Restrict both direct and indirect modification to a running kernel image.\n"
"\n"
"USAGE: kimglock [--help] [-p PROFILE] [-b CMDs]\n"
"\n"
"EXAMPLES:\n"
"  # Allow profile: access to kernel image is allowed. Default.\n"
"  kimglock\n\n"
"  kimglock --profile=allow\n\n"
"  # Baseline profile: allow access to kernel image only from tasks in\n"
"  # initial pid and network namespace.\n"
"  kimglock --profile=baseline\n\n"
"  # Baseline profile: allow kernel image access only from tasks in initial\n"
"  # pid and network namespaces but block access to /dev/{mem,kmem,port}.\n"
"  kimglock --profile=baseline --block=dev_mem\n\n"
"  # Restricted profile: direct and indirect access to kernel image is denied.\n"
"  kimglock --profile=restricted\n";

static const struct argp_option opts[] = {
        { "profile", 'p', "PROFILE", 0, "Profile to apply, one of the following: allow, baseline or restricted. Default value is: allow." },
        { "block", 'b', "CMDs", 0, "Block commands, possible values: 'unsigned_module, unsafe_module_parameters, dev_mem, kexec, hibernation, pci_access, ioport, msr, bpf_write' " },
        { "maps-filter", 'm', "cgroupmap,pidnsmap,netnsmap", 0, "Baseline map filter to allow tasks that are in these maps to access kernel image."},
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
                if (strlen(arg) + 1 > 512) {
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

static int pre_setup_bpf_args_map(struct kimglock_bpf *skel)
{
        if (!opt.debug)
                return 0;

        skel->rodata->debug = true;

        return 0;
}

static int push_param(int m, const char *op)
{
        uint32_t k = 0, val = KIMGLOCK_BLOCK_OP;

        if (strstr(op, "unsigned_module") != NULL) {
                k = LOCK_KIMG_MODULE_SIGNATURE;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }
        if (strstr(op, "dev_mem") != NULL) {
                k = LOCK_KIMG_DEV_MEM;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }
        if (strstr(op, "efi_test") != NULL) {
                k = LOCK_KIMG_EFI_TEST;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "kexec") != NULL) {
                k = LOCK_KIMG_KEXEC;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "hibernation") != NULL) {
                k = LOCK_KIMG_HIBERNATION;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "pci_access") != NULL) {
                k = LOCK_KIMG_PCI_ACCESS;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "ioport") != NULL) {
                k = LOCK_KIMG_IOPORT;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "msr") != NULL) {
                k = LOCK_KIMG_MSR;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "acpi_tables") != NULL) {
                k = LOCK_KIMG_ACPI_TABLES;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "pcmcia_cis") != NULL) {
                k = LOCK_KIMG_PCMCIA_CIS;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "tiocsserial") != NULL) {
                k = LOCK_KIMG_TIOCSSERIAL;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "unsafe_module_parameters") != NULL) {
                k = LOCK_KIMG_MODULE_PARAMETERS;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "mmiotrace") != NULL) {
                k = LOCK_KIMG_MMIOTRACE;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "debugfs") != NULL) {
                k = LOCK_KIMG_DEBUGFS;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "xmon_wr") != NULL) {
                k = LOCK_KIMG_XMON_WR;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "bpf_write") != NULL) {
                k = LOCK_KIMG_BPF_WRITE_USER;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        if (strstr(op, "kcore") != NULL) {
                k = LOCK_KIMG_KCORE;
                bpf_map_update_elem(m, &k, &val, BPF_ANY);
        }

        return 0;
}

/* Setup bpf map options */
static int setup_bpf_args_map(struct kimglock_bpf *skel)
{
        uint32_t key = KIMGLOCK_PROFILE, val = 0;
        int f;

        opt.perm_int = 0;

        f = bpf_map__fd(skel->maps.kimglock_args_map);
        if (f < 0) {
                fprintf(stderr, "%s: %s: error: failed to get bpf map fd: %d\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, f);
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

        key = KIMGLOCK_MAPS_FILTER;
        bpf_map_update_elem(f, &key, &opt.filter_int, BPF_ANY);

        key = KIMGLOCK_DEBUG;
        val = opt.debug ? 1 : 0;
        bpf_map_update_elem(f, &key, &val, BPF_ANY);

        f = bpf_map__fd(skel->maps.kimglock_block_map);
        if (f < 0) {
                fprintf(stderr, "%s: %s: error: failed to get kimglock_block_map fd: %d\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, f);
                return f;
        }

        if (opt.block_op)
                push_param(f, opt.block_op);

        return 0;
}

int main(int argc, char **argv)
{
        static const struct argp argp = {
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

        struct kimglock_bpf *skel = NULL;
        struct bpf_program *prog = NULL;
        struct bpf_object *obj = NULL;
        struct stat st;
        char *buf = NULL;
        int err, i;

        err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
        if (err)
                return err;

        err = is_lsmbpf_supported();
        if (err) {
                fprintf(stderr, "%s: %s: error: failed to check LSM BPF support\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK);
                return err;
        }

        err = bump_memlock_rlimit();
        if (err) {
                fprintf(stderr, "%s: %s: error: failed to increase rlimit: %s\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, strerror(errno));
                return err;
        }

        err = stat(kimg_security_map.pin_path, &st);
        if (err == 0) {
                fprintf(stdout, "%s: %s already loaded nothing todo, please delete pinned directory '%s' "
                        "to be able to run it again.\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, kimg_security_map.pin_path);
                return -EALREADY;
        }

        buf = malloc(128);
        if (!buf) {
                fprintf(stderr, "%s: %s: error: failed to allocate memory\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK);
                return -ENOMEM;
        }

        memset(buf, 0, 128);

        skel = kimglock_bpf__open();
        if (!skel) {
                fprintf(stderr, "%s: %s: error: failed to open BPF skelect\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK);
                err = -EINVAL;
                goto cleanup;
        }

        obj = bpf_object__open_mem(skel->skeleton->data, skel->skeleton->data_sz, NULL);
        if (!obj) {
                fprintf(stderr, "%s: %s: error: failed to open bpf mem\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK);
                err = libbpf_get_error(link);
                goto cleanup;
        }

        err = bpf_reuse_shared_maps(obj);
        if (err < 0) {
                fprintf(stderr, "%s: %s: failed to reuse shared bpf maps: %d\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, err);
        }

        pre_setup_bpf_args_map(skel);

        err = kimglock_bpf__load(skel);
        if (err) {
                fprintf(stderr, "%s: %s: error: failed to load BPF skelect: %d\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, err);
                goto cleanup;
        }

        err = setup_bpf_args_map(skel);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to setup bpf opt map: %d\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, err);
                goto cleanup;
        }

        err = push_host_init_ns(skel->maps.bpflock_pidnsmap);
        if (err < 0) {
                fprintf(stderr, "%s: %s: error: failed to setup bpf shared maps: %d\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, err);
                goto cleanup;
        }

        mkdir(BPFLOCK_PIN_PATH, 0700);
        mkdir(kimg_security_map.pin_path, 0700);

        err = bpflock_bpf_object__pin(skel->obj, kimg_security_map.pin_path);
        if (err) {
                libbpf_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "%s: %s: error: failed to pin bpf obj into '%s'\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, buf);
                goto cleanup;
        }

        i = 0;
        bpf_object__for_each_program(prog, skel->obj) {
                struct bpf_link *link = bpf_program__attach(prog);
                err = libbpf_get_error(link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: %s: error: failed to attach BPF programs: %s\n",
                                LOG_BPFLOCK, LOG_KIMGLOCK, strerror(-err));
                        goto cleanup;
                }

                err = bpf_link__pin(link, kimg_prog_links[i].link);
                if (err) {
                        libbpf_strerror(err, buf, sizeof(buf));
                        fprintf(stderr, "%s: %s: error: failed to pin bpf obj into '%s'\n",
                                LOG_BPFLOCK, LOG_KIMGLOCK, buf);
                        goto cleanup;
                }
                i++;
        }

        if (opt.perm_int == BPFLOCK_P_RESTRICTED) {
                printf("%s: bpf=%s success profile=restricted - access to kernel image is denied - delete directory '%s' to re-enable\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, kimg_security_map.pin_path);
        } else if (opt.perm_int == BPFLOCK_P_BASELINE) {
                printf("%s: bpf=%s success profile=baseline - access to kernel image is restricted only to initial pid and network namespaces - delete directory '%s' to re-enable\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, kimg_security_map.pin_path);
        } else {
                printf("%s: bpf=%s success profile=allow - access to kernel image is allowed - delete directory '%s' to disable access logging.\n",
                        LOG_BPFLOCK, LOG_KIMGLOCK, kimg_security_map.pin_path);
        }

cleanup:
        kimglock_bpf__destroy(skel);
        free(buf);
        return err;
}
