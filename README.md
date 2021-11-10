# `bpflock` - Lock Linux machines

`bpflock` - eBPF driven security for locking and auditing Linux machines.

#### This is a Work In Progress:

* `bpflock` is currently in experimental stage and some BPF programs are being updated.

* Programs will be updated soon to use [Cilium ebpf library](https://github.com/cilium/ebpf/) and turned into a small daemon.

## Sections

* [1. Introduction](https://github.com/linux-lock/bpflock#1-introduction)
* - [1.1 Security features](https://github.com/linux-lock/bpflock#11-security-features)
  - [1.2 Semantics](https://github.com/linux-lock/bpflock#12-semantics)
* [2. Build](https://github.com/linux-lock/bpflock#2-build)
* [4. Deployment]


## 1. Introduction

`bpflock` is designed to work along side, init programs, systemd or container managers to protect Linux machines using a system wide approach. The `"plan"` is to make it usable on kubernetes deployments, servers, Linux-IoT devices, and work stations.

`bpflock` combines multiple bpf independent programs to restrict access to a wide range of Linux features, only services like init, systemd or container managers that run in the initial [mnt namespace](https://man7.org/linux/man-pages/man7/namespaces.7.html) will be able to access all Linux kernel features, other tasks including containers that run on their own namespaces will be
restricted or completely blocked.

`bpflock` uses [LSM BPF](https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html) to implement its security features.

Note: `bpflock` is able to restrict root access to some features, however it does not protect against evil root users. Such users are able to disable `bpflock` if `/sys` file system is writable.


## 1.1 Security features

`bpflock` bpf programs offer multiple security protections and are able to restrict access to the following features:

* [Hardware additions](https://github.com/linux-lock/bpflock/tree/main/doc/hardware-additions.md)

  - [USB additions protection](https://github.com/linux-lock/bpflock/tree/main/doc/hardware-additions.md#1-usb-additions-protection)

* [Memory protections](https://github.com/linux-lock/bpflock/tree/main/doc/memory-protections.md)

  - [Kernel image lock down](https://github.com/linux-lock/bpflock/tree/main/doc/memory-protections.md#1-kernel-image-lock-down)
  - [Kernel modules protection](https://github.com/linux-lock/bpflock/tree/main/doc/memory-protections.md#2-kernel-modules-protections)
  - [BPF protection](https://github.com/linux-lock/bpflock/tree/main/doc/memory-protections.md#3-bpf-protection)
  - [Execution of Memory ELF binaries](https://github.com/linux-lock/bpflock/tree/main/doc/memory-protections.md#4-execution-of-memory-elf-binaries)

* [Filesystem protections](https://github.com/linux-lock/bpflock/tree/main/doc/filesystem-protections.md)

  - Read-only root filesystem protection
  - sysfs protection

* [Namespaces protections](https://github.com/linux-lock/bpflock#34-namespaces-protections)

### 1.2 Semantics

The semantic of all programs is:

* Permission: each program supports three different permission models.
  - `allow|none`: access is allowed.
  - `deny`: access is denied for all processes.
  - `restrict`: access is allowed only from processes that are in the initial mnt and other namespaces. This allows init, systemd and container managers to properly access all functionality.


* Allowed or blocked operations/commands:
  when a program runs under the allow or restrict permission model, it can defines a list of allowed or blocked commands.
  - `allow`: comma-separated list of allowed commands.
  - `block`: comma-separated list of blocked commands.


## 2. Build

First we need the right dependencies:

* [libbpf](https://github.com/linux-lock/bpflock#21-libbpf)
* [kernel version 5.15](https://github.com/linux-lock/bpflock#22-kernel)
* [Libraries and compilers](https://github.com/linux-lock/bpflock#23-libraries-and-compilers)
* [Build binaries](https://github.com/linux-lock/bpflock#24-build-binaries)


### 2.1 libbpf

This repository uses libbpf as a git-submodule. After cloning this repository you need to run the command:

```bash
git submodule update --init
```

If you want submodules to be part of the clone, you can use this command:

```bash
git clone --recurse-submodules https://github.com/linux-lock/bpflock
```

### 2.2 kernel

Tested on a kernel 5.15.0-rc5+ (will pin to 5.15 when released) with the following options:

```code
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBES=y
CONFIG_LSM="...,bpf"
CONFIG_BPF_LSM=y
```

### 2.3 Libraries and compilers

#### Ubuntu

To build install the following packages:
  ```bash
  sudo apt install -y bison build-essential flex \
        git libllvm10 llvm-10-dev libclang-10-dev \
        zlib1g-dev libelf-dev libfl-dev
  ```

### 2.4 Build binaries

Get libbpf if not:
```
git submodule update --init
```

To build just run:
```bash
make
```

All build binaries and libraries will be produced in `build/dist/` directory.

Current build process was inspired from: https://github.com/iovisor/bcc/tree/master/libbpf-tools

## 4. Deployment
