# bpflock - Lock Linux machines

bpflock - eBPF driven security for locking and auditing Linux machines.


## Work In Progress

This is a Work In Progress:

* BPF programs are being updated

* Programs will be updated soon to use [Cilium ebpf library](https://github.com/cilium/ebpf/) and turned into a small daemon for embedded Linux.


## 1. Design

bpflock is designed to work along side container managers to protect Linux machines using a system wide approach.

bpflock will sandbox all containers and protect the Linux machine, only services like container managers or systemd manager will be able to access all Linux kernel features, all other containers that run on their own namespaces will be restricted or completely blocked.

bpflock uses LSM bpf to implement its security features.

## 2. Protections


### 2.2 kernel lock down

kernelmem implements access restriction to prevent both direct and indirect access to a running kernel image.

It uses the [kernel lockdown LSM](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) to protect against unauthorized modification of the kernel image and to prevent access to security and cryptographic data located in kernel memory.

**Note: options are not stable and this is a moving target**.

It supports following options:

 * Permission:
    - allow|none: kernelmem is disabled. All access is allowed.
    - deny: direct and indirect access to a running kernel image is denied for all processes and containers, this will force the integrity mode.
    - restrict: access is allowed only from processes that are in the initial mnt namespace. This allows systemd and container managers to
    properly setup the working environment or communicate with hardware. Default permission. 

 * Restricted access:
   - integrity: run in integrity mode, kernel features that allow userland to modify the running kernel are disabled.

 * Special access exceptions in case of restricted access:
   - unsigned_module: allow unsigned module loading.
   - dev_mem: access to /dev/{mem,kmem,port} is allowed.
   - kexec: kexec of unsigned images is allowed.
   - hibernation: hibernation is allowed.
   - ioport: raw io port access is allowed.
   - msr: raw msr access is allowed.
   - debugfs: debugfs is allowed.
   - xmon_rw: xmon write access is allowed.
   - bpf_write: use of bpf write to user RAM is allowed.


Examples:

* Deny direct and indirect access for all processes:
  ```bash
  sudo kernelmem -p deny
  ```

* All access is allowed:
  ```bash
  sudo kernelmem -p none
  ```

* Restrict mode, access is allowed for processes in the initial mnt namespace:
  ```bash
  sudo kernelmem
  sudo kernelmem -p restrict
  ```

* Restrict mode, disable all and allow only bpf writes to user RAM from processes in the initial mnt namespace:
  ```bash
  sudo kernelmem -p restrict -integrity -a bpf_write
  ``` 

* Restrict mode, disable all and allow debugfs, ioport and unsigned module loading from processes in the initial mnt namespace: 
  ```bash
  sudo kernelmem -p restrict -integrity -a debugfs,ioport,unsigned_module
  ``` 

To disable this program delete the pinned file `/sys/fs/bpf/bpflock/kernelmem`. Re-executing will enable it again.


### 2.3 bpf protection

disablebpf implements access restrictions on bpf syscall.

It supports following options:

 * Permission:
    - allow|none: bpf is allowed.
    - deny: bpf syscall and all its commands are denied for all processes and containers on the system.
    - restrict: bpf is allowed only from processes that are in the initial mnt namespace. This allows systemd or container managers to properly use bpf. Default value.

 * List of commands to allow in case permission is restrict:
    - map_create: allow creation of bpf maps.
    - btf_load: allow loading BPF Type Format (BTF) metadata into the kernel.
    - prog_load: allow loading bpf programs.
    - All other commands are allowed by default.
    
    If allowed command is not set, then all bpf commands are allowed. If one of the three is set, then the two others are blocked.


Make sure to execute this program last during boot and after all necessary bpf programs have been loaded. For containers workload to disable this program, delete the pinned file `/sys/fs/bpf/bpflock/disable-bpf`. Re-executing will enable it again.


## Applications

* disableautomod: will block users (or
  attackers) from auto-loading modules. This will block unprivileged code from loading possible vulnerable modules, however it is not effective against code running with root privileges, where it is able to load modules explicitly.  

* disablebpf: will disable the bpf() syscall completely for all, including systemd or the container manager. This attended to be the last protection after applying other protections.

* restrictfilesystems: disables access to some file systems, as this is attended to be used with restricting mounting filesystems to make sure that even during embedded systems updates we keep window of arbitrary filesystem access restricted.


## 3. Build and Dependencies


### 3.1 libbpf as git-submodule

This repository uses libbpf as a git-submodule. After cloning this repository you need to run the command:

```bash
git submodule update --init
```

If you want submodules to be part of the clone, you can use this command:

```bash
git clone --recurse-submodules https://github.com/linux-lock/bpflock
```

### 3.2 kernel

Tested on a kernel +5.11 with the following options:

```code
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBES=y
CONFIG_LSM="...,bpf"
CONFIG_BPF_LSM=y
```

### 3.3 Other dependencies

* Ubuntu
  ```bash
   sudo apt install -y bison build-essential flex git \
        libllvm7 llvm-7-dev libclang-7-dev zlib1g-dev \
        libelf-dev libfl-dev
  ```


### 3.4 Build

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