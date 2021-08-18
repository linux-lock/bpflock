# bpflock - Lock Linux machines

bpflock - eBPF driven security for locking and auditing Linux machines.


## Work In Progress

This is a Work In Progress:

* BPF programs are being updated

* Tt will be updated soon to use [Cilium ebpf library](https://github.com/cilium/ebpf/) and turned into a small daemon. 


## Design

This is designed for embedded Linux where applications are sandboxed or executed in their own mnt namespace using systemd or a container manager. bpflock LSM based security features will apply to the whole system, and block access to kernel features that are being accessed by applications not in the init mnt namespace.


## BPF LSM Applications

* disablemoduleautoload: will block users (or
  attackers) from auto-loading modules. This will block unprivileged code from loading possible vulnerable modules, however it is not effective against code running with root privileges, where it is able to load modules explicitly.  

* disablebpf: will disable the bpf() syscall completely for all, including systemd or the container manager. This attended to be the last protection after applying other protections.

* restrictfilesystems: disables access to some file systems, as this is attended to be used with restricting mounting filesystems to make sure that even during embedded systems updates we keep window of arbitrary filesystem access restricted.


## Dependencies

### libbpf as git-submodule

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

### Build dependencies

- Ubuntu
```bash
sudo apt install -y bison build-essential flex git \
        libllvm7 llvm-7-dev libclang-7-dev zlib1g-dev \
        libelf-dev libfl-dev
```


## Build

Current build process was inspired by: https://github.com/iovisor/bcc/tree/master/libbpf-tools

To build first get the libbpf submodule then run "make". All build binaries will be produced in `src/` directory.