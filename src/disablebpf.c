#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/bpf.h>
#include "disablebpf.skel.h"
#include "trace_helpers.h"
#include "bpflock_utils.h"

static const char pin_path[] = "/sys/fs/bpf/bpflock/disable-bpf";

int main(int argc, char **argv)
{
	struct disablebpf_bpf *skel;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	char buf[100];
	int err;

	err = is_lsmbpf_supported();
	if (err) {
		fprintf(stderr, "%s: error: failed to check LSM BPF support\n",
			LOG_BPFLOCK);
		return err;
	}

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "error: failed to increase rlimit: %s\n",
				strerror(errno));
		return 1;
	}

	skel = disablebpf_bpf__open();
	if (!skel) {
		fprintf(stderr, "error: failed to open BPF skelect\n");
		return 1;
	}

	err = disablebpf_bpf__load(skel);
	if (err) {
		fprintf(stderr, "error: failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	prog = bpf_program__next(NULL, skel->obj);
	if (!prog) {
		fprintf(stderr, "error: failed to find LSM disable bpf program!\n");
		err = -ENOENT;
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "error: failed to attach BPF programs: %s\n",
				strerror(-err));
		goto cleanup;
	}

	err = bpf_link__pin(link, pin_path);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "%s: error: failed to pin '%s'\n",
			LOG_BPFLOCK, buf);
		goto cleanup;
	}

	printf("%s: success: The bpf() syscall is now disabled - pinned file '%s' to re-enable\n",
	       LOG_BPFLOCK, pin_path);

cleanup:
	bpf_link__destroy(link);
	//bpf_link__destroy(link);
	disablebpf_bpf__destroy(skel);

	return err != 0;
}
