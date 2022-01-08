# bpflock - Lock Linux machines

`bpflock` - eBPF driven security for locking and auditing Linux machines.

Note: bpflock is currently in **experimental stage**, security semantics may change, some BPF programs will be updated to use [Cilium ebpf library](https://github.com/cilium/ebpf/).

## Sections

* [1. Introduction](https://github.com/linux-lock/bpflock#1-introduction)
  - [1.1 Security features](https://github.com/linux-lock/bpflock#11-security-features)
  - [1.2 Semantics](https://github.com/linux-lock/bpflock#12-semantics)
* [2. Deployment](https://github.com/linux-lock/bpflock#2-deployment)
* [3. Documentation](https://github.com/linux-lock/bpflock#3-documentation)
* [4. Build](https://github.com/linux-lock/bpflock#3-build)

## 1. Introduction

bpflock combines multiple bpf programs to strength Linux security. By restricting access to a various range of Linux features, bpflock is able to reduce the attack surface and block some well known attack techniques.

Only programs like systemd, container managers and other containers/programs that run in the host [pid namespace](https://man7.org/linux/man-pages/man7/namespaces.7.html) will be able to access those features. Containers that run on their own namespace will be restricted or completely blocked. The restriction will be augmented in the future to perform per cgroupv2 filtering.

bpflock protects Linux machines using a system wide approach taking advantage of [Linux Security Modules + BPF](https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html).

Notes:
- bpflock is not a mandatory access control labeling solution, and it does not intent to replace [AppArmor](https://apparmor.net/), [SELinux](https://github.com/SELinuxProject/selinux), and other MAC solutions.
- bpflock is able to restrict root to access certain Linux features, however it does not protect against evil root users that can disable it.

## 1.1 Security features

bpflock bpf programs offer multiple security protections that can be classified as:

* [Hardware Addition Attacks](https://github.com/linux-lock/bpflock/tree/main/docs/hardware-additions.md)
  - [USB Additions Protection](https://github.com/linux-lock/bpflock/tree/main/docs/hardware-additions.md#1-usb-additions-protection)

* [Memory Protections](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md)
  - [Kernel Image Lockdown](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#1-kernel-image-lockdown)
  - [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protections)
  - [BPF Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection)
  - [Execution of Memory ELF binaries](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#4-execution-of-memory-elf-binaries)

* [Filesystem Protections](https://github.com/linux-lock/bpflock/tree/main/docs/filesystem-protections.md)

  - Read-only root filesystem protection
  - sysfs protection

* [Linux Namespaces Protections](https://github.com/linux-lock/bpflock#34-namespaces-protections)

* Network protections

  - bpflock may include in future a simple network protection that can be used in single machine workload or Linux-IoT, but will not include a Cloud Native protection. [Cilium](https://github.com/cilium/cilium) and other kubernetes CNI related solutions are by far better.

### 1.2 Semantics

bpflock tries to keep the security semantics simple without introducing complex policies. It uses a simple `permission` model that takes the following values:

* `permission`: each bpf program supports three different permission models.
  - `allow|none` : access is allowed. It can be used to log security events.
  - `restrict` : access is restricted. Only processes that are in the initial pid namespace.
  - `deny` : access is denied for all processes.

* `Allowed` or `blocked` operations/commands:

  Depending on the `permission` model a list of allowed or blocked commands can be specified with:
  - `allow` : comma-separated list of allowed operations. Valid under `restrict` and `deny` permissions.
  - `block` : comma-separated list of blocked operations. Valid under `restrict` permission.

For configuration examples check [bpflock configuration examples](https://github.com/linux-lock/bpflock/tree/main/deploy/configs/README.md)


## 2. Deployment

### 2.1 Prerequisites

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

### 2.2 Docker deployment

```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged -v /sys/kernel/security:/sys/kernel/security -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock:latest
```

## 3. Documentation

Documentation files can be found [here](https://github.com/linux-lock/bpflock/tree/main/docs/).

## 4. Build

bpflock uses [docker BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/) to build and [Golang](https://go.dev/doc/install) for running tests.

### 4.1 libbpf

This repository uses libbpf as a git-submodule. After cloning this repository you need to run the command:

```bash
git submodule update --init
```

If you want submodules to be part of the clone, you can use this command:

```bash
git clone --recurse-submodules https://github.com/linux-lock/bpflock
```

### 4.2 Libraries and compilers

#### Ubuntu

To build install the following packages:
  ```bash
  sudo apt install -y bison build-essential flex \
        git libllvm10 llvm-10-dev libclang-10-dev \
        zlib1g-dev libelf-dev libfl-dev
  ```

### 4.3 Build binaries

Get libbpf if not:
```
git submodule update --init
```

To build just run:
```bash
make
```

All build binaries and libraries will be produced in `build/dist/` directory.

## Credits

bpflock uses lot of resources including source code from the [Cilium](https://github.com/cilium/cilium) and
[bcc](https://github.com/iovisor/bcc) projects.

## License

The bpflock user space components are licensed under the [Apache License, Version 2.0](https://github.com/linux-lock/bpflock/blob/main/LICENSE). The BPF code where it is noted is licensed under the [General Public License, Version 2.0](https://github.com/linux-lock/bpflock/blob/main/src/COPYING).
