# bpflock - Lock Linux machines

bpflock - eBPF driven security for locking and auditing Linux machines.


## Work In Progress

This is a Work In Progress:

* BPF programs are being updated

* Programs will be updated soon to use [Cilium ebpf library](https://github.com/cilium/ebpf/) and turned into a small daemon for embedded Linux.


## Design

bpflock is designed to work along side container managers to protect Linux machines using a system wide approach.

bpflock will sandbox all containers and protect the Linux machine, only services like container managers or systemd manager will be able to access all Linux kernel features, all other containers that run on their own namespaces will be restricted or completely blocked.

bpflock uses LSM bpf to implement its security features.


## BPF LSM Applications

* disableautomod: will block users (or
  attackers) from auto-loading modules. This will block unprivileged code from loading possible vulnerable modules, however it is not effective against code running with root privileges, where it is able to load modules explicitly.  

* disablebpf: will disable the bpf() syscall completely for all, including systemd or the container manager. This attended to be the last protection after applying other protections.

* restrictfilesystems: disables access to some file systems, as this is attended to be used with restricting mounting filesystems to make sure that even during embedded systems updates we keep window of arbitrary filesystem access restricted.


## Build and Dependencies


### libbpf as git-submodule

This repository uses libbpf as a git-submodule. After cloning this repository you need to run the command:

```bash
git submodule update --init
```

If you want submodules to be part of the clone, you can use this command:

```bash
git clone --recurse-submodules https://github.com/linux-lock/bpflock
```

### kernel

Tested on a kernel +5.11 with the following options:

```code
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBES=y
CONFIG_LSM="...,bpf"
CONFIG_BPF_LSM=y
```

### Other dependencies

* Ubuntu
  ```bash
   sudo apt install -y bison build-essential flex git \
        libllvm7 llvm-7-dev libclang-7-dev zlib1g-dev \
        libelf-dev libfl-dev
  ```


### Build

Get libbpf if not:
```
git submodule update --init
```

Build:
```bash
make
```

All build binaries will be produced in `src/` directory.

Current build process was inspired by: https://github.com/iovisor/bcc/tree/master/libbpf-tools