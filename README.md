# bpflock - Lock Linux machines

![Bpflock Logo](docs/images/bpflock-logo-small.png)

bpflock - eBPF driven security for locking and auditing Linux machines.

Note: bpflock is currently in **experimental stage**, it may break, options and security semantics may change, some BPF programs will be updated to use [Cilium ebpf library](https://github.com/cilium/ebpf/).

## Sections

* [1. Introduction](https://github.com/linux-lock/bpflock#1-introduction)
* [2. Functionality Overview](https://github.com/linux-lock/bpflock#2-functionality-overview)
  - [2.1 Security features](https://github.com/linux-lock/bpflock#21-security-features)
  - [2.2 Semantics](https://github.com/linux-lock/bpflock#12-semantics)
* [3. Deployment](https://github.com/linux-lock/bpflock#2-deployment)
* [4. Documentation](https://github.com/linux-lock/bpflock#3-documentation)
* [5. Build](https://github.com/linux-lock/bpflock#3-build)

## 1. Introduction

bpflock uses [eBPF](https://ebpf.io/) to strength Linux security. By restricting access to a various range of Linux features, bpflock is able to reduce the attack surface and block some well known attack techniques.

Only programs like container managers, systemd and other containers/programs that run in the host [pid
namespace](https://man7.org/linux/man-pages/man7/namespaces.7.html) may be able to access those features, containers
that run on their own namespace will be restricted. If bpflock bpf programs run under a `restricted` profile then all
programs/containers will be denied access even privileged ones. The filtering model will be augmented soon to include
per cgroupv2 filetring.

bpflock protects Linux machines by taking advantage of multiple security features including [Linux Security Modules + BPF](https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html).

Architecture and Security design notes:
- bpflock is not a mandatory access control labeling solution, and it does not intent to replace
[AppArmor](https://apparmor.net/), [SELinux](https://github.com/SELinuxProject/selinux), and other MAC solutions.
bpflock uses a simple declarative security profile.
- bpflock offers multiple small bpf programs that can be reused in multiple contexts from Cloud Native deployments to Linux IoT devices.
- bpflock is able to restrict root to access certain Linux features, however it does not protect against evil root users that can disable it.

## 2. Functionality Overview

### 2.1 Security features

bpflock offer multiple security protections that can be classified as:

* [Memory Protections](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md)
  - [Kernel Image Lock-down](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#1-kernel-image-lock-down)
  - [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protection)
  - [BPF Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection)

* [Process Protections](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md)
  - [Fileless Memory Execution](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md#fileless-memory-execution)
  - [Namespaces protection](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md#namespaces-protection)

* [Hardware Addition Attacks](https://github.com/linux-lock/bpflock/tree/main/docs/hardware-additions.md)
  - [USB Additions Protection](https://github.com/linux-lock/bpflock/tree/main/docs/hardware-additions.md#1-usb-additions-protection)

* System and Application tracing
  - Trace application execution
  - Trace privileged system operations

* Filesystem Protections
  - Read-only root filesystem protection
  - sysfs protection

* Network protections

  - bpflock may include in future a simple network protection that can be used in single machine workload or Linux-IoT, but will not include a Cloud Native protection. [Cilium](https://github.com/cilium/cilium) and other kubernetes CNI related solutions are by far better.

### 2.2 Semantics

bpflock keeps the security semantics simple. It support three declarative profiles models to broadly cover the security sepctrum, and restrict access to specific Linux features.

Also bpflock creates multiple shared bpf maps under `/sys/fs/bpf/` to store per container and namespaces profiles. The following: `bpflock_cgroupmap`, `bpflock_pidnsmap` and `bpflock_netnsmap` are used to check per pod, container or app access.

* `profile`: this is the global profile that takes one of the followings.
  - `allow|none|privileged` : they are the same, they define the least secure profile. In this profile access is logged and allowed for all processes. Useful to log security events.
  - `baseline` : minimal restricive profile, only programs that are present in the `bpflock_cgroupmap`, `bpflock_pidnsmap` and `bpflock_netnsmap` are allowed according to their per context profile. By default the `bpflock_pidnsmap` contains the initial pid namespace, therefore all processes in the initial pid namespace are allowed.
  - `restricted` : heavily restricted profile where access is denied for all processes. The shared bpflock maps are not consulted under this global profile.

* `Allowed` or `blocked` operations/commands:

  Under the global `baseline` profile, a list of allowed or blocked commands can be specified that will be applied to the type of security protection.
  - `--protection-allow` : comma-separated list of allowed operations. Valid under `baseline` profile, this is useful for applications that are too specific and require privileged operations, it will reduce the use of the `allow | privileged` profile and offer a case-by-case definitions.
  - `--protection-block` : comma-separated list of blocked operations. Valid under `baseline` profile, useful to achieve a more `restricted` profile. The other way from `restricted` to `baseline` is not supported.

For bpf security examples check [bpflock configuration examples](https://github.com/linux-lock/bpflock/tree/main/deploy/configs/)

**Note: the above semantics may change.**.

## 3. Deployment

### 3.1 Prerequisites

bpflock needs the following:

* Linux kernel version >= 5.15 with the following configuration:

  ```code
  CONFIG_BPF_SYSCALL=y
  CONFIG_DEBUG_INFO=y
  CONFIG_DEBUG_INFO_BTF=y
  CONFIG_KPROBES=y
  CONFIG_LSM="...,bpf"
  CONFIG_BPF_LSM=y
  ```

* Obviously a BTF enabled kernel.


### 3.2 Docker deployment

To run using the default `allow` or `privileged` profile (the least secure profile):
```bash
docker run --name bpflock -it --rm --cgroupns=host \
  --pid=host --privileged \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

Then in another terminal read from the tracing pipe to see logs:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Note: this is a temporary testing solution, bpflock will soon display all logs directly.

#### Kernel Modules Protection

To apply [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protection)
run with environment variable `BPFLOCK_KMODLOCK_PROFILE=baseline` or `BPFLOCK_KMODLOCK_PROFILE=restricted`:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_KMODLOCK_PROFILE=baseline" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

Example:
```bash
$ sudo unshare -f -p bash
# modprobe xfs
modprobe: ERROR: could not insert 'xfs': Operation not permitted
```

```
modprobe-399022  [002] d...1 427205.192790: bpf_trace_printk: bpflock bpf=kmodlock pid=399022 event=module load from non init pid namespace status=denied (baseline)
```

#### Kernel Image Lock-down

To apply [Kernel Image Lock-down](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#1-kernel-image-lock-down) run with environment variable `BPFLOCK_KIMGLOCK_PROFILE=baseline` or `BPFLOCK_KIMGLOCK_PROFILE=restricted`:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_KIMGLOCK_PROFILE=baseline" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

#### BPF Protection

To apply [bpf restriction](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection) run with environment variable `BPFLOCK_BPFRESTRICT_PROFILE=baseline` or `BPFLOCK_BPFRESTRICT_PROFILE=restricted`:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_BPFRESTRICT_PROFILE=baseline" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

Example:
```bash
$ sudo unshare -f -p bash
# bpftool prog
Error: can't get next program: Operation not permitted
```

```
bpftool-399330  [002] d...1 427673.628475: bpf_trace_printk: bpflock bpf=bpfrestrict pid=399330 comm=bpftool event=bpf() from non init pid namespace

bpftool-399330  [002] d...1 427673.628522: bpf_trace_printk: bpflock bpf=bpfrestrict pid=399330 event=bpf() from non init pid namespace status=denied (baseline)
```

## 4. Documentation

Documentation files can be found [here](https://github.com/linux-lock/bpflock/tree/main/docs/).

## 5. Build

bpflock uses [docker BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/) to build and
[Golang](https://go.dev/doc/install) to make some checks and run tests. bpflock is built inside Ubuntu container that
downloads the standard golang package.

Run the following to build the bpflock docker container:
```bash
git submodule update --init --recursive
make
```

Bpf programs are built using libbpf. The docker image used is Ubuntu.


If you want to only build the bpf programs directly without using docker, then on Ubuntu:
```bash
sudo apt install -y pkg-config bison binutils-dev build-essential \
        flex libc6-dev clang-12 libllvm12 llvm-12-dev libclang-12-dev \
        zlib1g-dev libelf-dev libfl-dev gcc-multilib zlib1g-dev \
        libcap-dev libiberty-dev libbfd-dev
```

Then run:
```bash
make bpf-programs
```

In this case the generated programs will be inside the ./bpf/build/... directory.


## Credits

bpflock uses lot of resources including source code from the [Cilium](https://github.com/cilium/cilium) and
[bcc](https://github.com/iovisor/bcc) projects.

## License

The bpflock user space components are licensed under the [Apache License, Version 2.0](https://github.com/linux-lock/bpflock/blob/main/LICENSE). The BPF code where it is noted is licensed under the [General Public License, Version 2.0](https://github.com/linux-lock/bpflock/blob/main/src/COPYING).
