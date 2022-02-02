# Process Protections

## Sections

  - [Fileless Memory Execution](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md#fileless-memory-execution)


## Fileless Memory Execution

### Introduction

`filelesslock` implements restrictions on the execution of binaries from the memory.
Such techniques are abused by so called _fileless malwares_ where a program or an exploit downloads a binary/payload from the
internet and executes it directly from the memory, without leaving traces on the disk.

`filelesslock` detects the execution of anonymous files from RAM that where obtained by:

  - Anonymous files created by [`memfd_create()`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
  - [Shared memory](https://man7.org/linux/man-pages/man7/shm_overview.7.html) backed files
  - Files created with the `O_TMPFILE` `open()` flag, where the file is unlinked and not referenced on any filesystem before its execution.

### Why an eBPF-based solution ?

Classic tools like `ps` that read `/proc/$pid/comm` are restricted and can be easily tricked, as changing the process name to arbitrary values is
a standard feature of Linux with the [`prctl()`](https://man7.org/linux/man-pages/man2/prctl.2.html).

Some detection solutions go even further: read the `/proc` filesystem and get the binary that is pointed by
`/proc/$pid/exe`. However, this detection can also be bypassed by calling `prctl()` with
[`PR_SET_MM_EXE_FILE`](https://man7.org/linux/man-pages/man2/prctl.2.html) in order to link to another binary on the filesystem.
Actually, a lot of process properties including kernel memory maps can be changed by calling `prctl(PR_SET_MM,...)` in a
restrictive way of course.

We may also read `/proc/$pid/maps` to show mapped memory, but as usual it is racy: the process may just `execv()` into another
one, and at the time of reading, maps will show some other data, too late!

The most robust way is to use LSM, tracing or eBPF to trace the execution. A good candidate is when the corresponding
`binfmt` loader matches and the process execution hits the point of no return. At this time, we have gathered enough
information, we can access the `elf` header, and we are sure that such information can't be forged,
since handing execution to the corresponding process still did not happen. The
[mm_struct](https://elixir.bootlin.com/linux/latest/C/ident/mm_struct) is still attached to the
[Linux_binprm struct](https://elixir.bootlin.com/linux/latest/C/ident/linux_binprm), and the current task still has a
copy of the parent's `mm_struct`. This allows to query the appropriate information, log, or even take actions before
bad things happen.

For further reference, please see [fileless.bpf.c](https://github.com/linux-lock/bpflock/blob/main/bpf/fileless.bpf.c), where it checks if the executed file is linked or not on the filesystem.

### Usage

`filelesslock` supports the following options:

 * `profile`:
    - `allow|none|privileged`: Fileless execution is allowed for all processes on the system. Operation is logged.
    - `baseline`: Fileless execution is allowed only from processes that are in the initial pid namespace. This allows container managers, systemd, init, etc to properly set up bpf.
    - `restricted`: Fileless execution is denied for all processes on the system.

#### Examples:

* Allow profile:

  ```bash
  bpflock --filelesslock-profile=none
  bpflock --filelesslock-profile=allow
  bpflock --filelesslock-profile=privileged
  ```

* Baseline profile: filelessexecution is allowed from processes in the initial pid namespace.
  ```bash
  bpflock --filelesslock-profile=baseline
  ```

* Restricted profile: deny fileless execution for all processes.
  ```bash
  bpflock --filelesslock-profile=restricted
  ```

#### Notes:
- In its basic form, the `filelesslock` bpf program detects most common scenarios related to executing anonymous files. Great
examples can be found in the [commandline_cloaking github repo](https://github.com/pathtofile/commandline_cloaking) that
includes `memfd` examples.

- Running in `restricted` or `baseline` profiles may block [runc](https://github.com/opencontainers/runc), since it
creates an anonymous `memfd` file that re-executes itself. Hence, `filelesslock` should run under the `allow` or `privileged`
profile where the operation will be logged.

### Disable `filelesslock`

To disable `filelesslock`, delete the directory `/sys/fs/bpf/bpflock/filelesslock` and all its pinned content. Re-executing will enable it again.

If `/sys` filesystem is in read-only mode and can not be remounted in read-write mode, then `bpflock` `filelesslock` is pinned and can't be
disabled, unless you overwirte its correspondig bpf map values.
