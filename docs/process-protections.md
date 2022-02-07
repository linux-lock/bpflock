# Process Protections

## Sections

  - [Fileless Memory Execution](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md#fileless-memory-execution)


## Fileless Memory Execution

### Introduction

`filelesslock` - implements restrictions on executing binaries directly from the memory without touching the filesystem.
Such techniques are abused by so called _fileless malwares_ where a program or an exploit downloads a binary/payload from the
internet and executes it directly from the memory, without leaving traces on the disk.

filelesslock detects the execution of anonymous files from RAM that where obtained by:

  - Anonymous files created by [`memfd_create()`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
  - [Shared memory](https://man7.org/linux/man-pages/man7/shm_overview.7.html) backed files
  - Files created with the `O_TMPFILE` `open()` flag and the file is unlinked and not referenced on any filesystem before its execution.

Notes:
- - In its basic form, the `filelesslock` bpf program detects most common scenarios related to executing anonymous files. Great
examples can be found in the [commandline_cloaking github repo](https://github.com/pathtofile/commandline_cloaking) that
includes `memfd` examples.

- Running in `restricted` or `baseline` profiles may block [runc](https://github.com/opencontainers/runc) as it
creates an anonymous memfd file to re-execute itself. Hence bpflock filelesslock should run under the `allow` or `privileged` profile where the operation will be logged.

### Usage

It supports following options:

* `profile`: this is the global profile that takes one of the followings:
  - `allow|none|privileged` : they are the same, they define the least secure profile. In this profile access is logged and allowed for all processes. Useful to log security events.
  - `baseline` : restrictive profile where access is denied for all processes, except applications and containers that run in the host pid and network namespaces, or applications that are present in the allow `bpflock_cgroupmap`.
  - `restricted` : heavily restricted profile where access is denied for all processes.

Examples:

* Allow profile:
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_FILELESSLOCK_PROFILE=allow" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: fileless execution is allowed from processes in the initial pid and network namespaces.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_FILELESSLOCK_PROFILE=baseline" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Restricted profile: deny fileless execution for all processes.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_FILELESSLOCK_PROFILE=restricted" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

### Disable filelesslock

To disable filelesslock, delete the directory `/sys/fs/bpf/bpflock/filelesslock` and all its pinned content. Re-executing will enable it again.

If `/sys` filesystem is in read-only mode and can not be remounted in read-write mode, then `bpflock` `filelesslock` is pinned and can't be
disabled, unless you overwirte its correspondig bpf map values.
