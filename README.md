# bpflock - Lock Linux machines

bpflock - eBPF driven security for locking and auditing Linux machines.


## Work In Progress

This is a Work In Progress:

* BPF programs are being updated

* Programs will be updated soon to use [Cilium ebpf library](https://github.com/cilium/ebpf/) and turned into a small daemon.


## 1. Introduction

bpflock is designed to work along side systemd or container managers to protect Linux machines using a system wide approach. It can be used on kubernetes deployments, servers, Linux-IoT devices, and work stations.

bpflock combines multiple bpf programs to sandbox tasks and containers, only services like systemd or container managers that run in the initial [mnt namespace](https://man7.org/linux/man-pages/man7/namespaces.7.html) will be able to access all Linux kernel features, other tasks including containers that run on their own namespaces will be
restricted or completely blocked.

To read more about Linux namespaces: [Linux namespaces man pages](https://man7.org/linux/man-pages/man7/namespaces.7.html).

bpflock uses [LSM BPF](https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html) to implement its security features.

## 2. Security design

bpflock bpf programs are separated by security functionality, where each program can be launched independently without interfering with the rest. Combined together they allow to restrict or block the access to a wide range of Linux kernel features.

### 2.1 Security features

* [Memory protections](https://github.com/linux-lock/bpflock#31-memory-protections)

  - [Kernel image lock down](https://github.com/linux-lock/bpflock#311-kernel-image-lock-down)
  - [Kernel modules protection](https://github.com/linux-lock/bpflock#312-kernel-modules-protections)
  - [Execution of In-Memory-Only ELF binaries (memfd)](https://github.com/linux-lock/bpflock#313-execution-of-in-memory-only-elf-binaries)
  - [BPF protection](https://github.com/linux-lock/bpflock#314-bpf-protection)

* [Filesystem protections](https://github.com/linux-lock/bpflock#32-filesystem-protections)

  - Read-only root filesystem protection
  - sysfs protection

* [Namespaces protections](https://github.com/linux-lock/bpflock#33-namespaces-protections)


### 2.2 Semantics

The semantic of all programs is:

* Permission: each program supports three different permission models.
  - `allow|none`: access is allowed.
  - `deny`: access is denied for all processes.
  - `restrict`: access is allowed only from processes that are in the initial mnt and other namespaces. This allows systemd and container managers to properly access all functionality.


* Allowed or blocked operations/commands:
  when a program runs under the allow or restrict permission model, it can defines a list of allowed or blocked commands.
  - `allow`: comma-separated list of allowed commands.
  - `block`: comma-separated list of blocked commands.


## 3. Protections

### 3.1 Memory protections

#### 3.1.1 kernel image lock down

kimg - kernel image implements restrictions to prevent both direct and indirect access to a running kernel image.

It combines the [kernel lockdown](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) features and other Linux Security Module hooks to protect against unauthorized modification of the kernel image.

**Note: this is still a moving target. Options are not stable**.

kimg will restrict or block access to the following features:

  - Automatic loading of kernel modules. This will block users (or attackers) from auto-loading modules. Unprivileged code will not be able to load "vulnerable" modules, however it is not effective against code running with root privileges, where it is able to load modules explicitly.  
  - Loading of unsigned modules.
  - Unsafe usage of module parameters.
  - Access to `/dev/mem, /dev/kmem and /dev/port`.
  - Access to `/dev/efi_test`.
  - kexec of unsigned images.
  - Hibernation of the machine.
  - Direct PCI access.
  - Raw io port access.
  - Raw MSR registers access.
  - Modification of ACPI tables.
  - Direct PCMCIA CIS storage.
  - Reconfiguration of serial port IO.
  - Usage of the ioperm and iopl instructions on x86. 
  - Debugfs access.
  - xmon write access.
  - bpf writes to user RAM.


kimg supports the following options:

 * Permission:
    - allow|none: kimg is disabled. All access is allowed.
    - deny: direct and indirect access to a running kernel image is denied for all processes and containers.
    - restrict: access is allowed only from processes that are in the initial mnt namespace. This allows systemd and container managers to
    properly setup the working environment or communicate with hardware. Default permission. 

 * Blocked access:
   If in restrict mode, then the integrity mode of kernel lock down will be enforced for all processes that are not in the initial mnt namespace, and [kernel features](https://github.com/linux-lock/bpflock#311-kimg-options) to modify the running kernel are blocked.

 * Special access exceptions:
   If running under `restrict` permission model, then a coma-separated list of allowed features can be specified:
   - `unsigned_module` : allow unsigned module loading.
   - `autoload_module` : allow automatic module loading.
   - `unsafe_module_parameters` : allow module parameters that directly specify hardware
         parameters to drivers 
   - `dev_mem` : access to /dev/{mem,kmem,port} is allowed.
   - `kexec` : kexec of unsigned images is allowed.
   - `hibernation` : hibernation is allowed.
   - `pci_access` : allow direct PCI BAR access.
   - `ioport` : raw io port access is allowed.
   - `msr` : raw msr access is allowed.
   - `mmiotrace` : tracing memory mapped I/O is allowed.
   - `debugfs` : debugfs is allowed.
   - `xmon_rw` : xmon write access is allowed.
   - `bpf_write` : use of bpf write to user RAM is allowed.


Examples:

* Deny direct and indirect access for all processes:
  ```bash
  sudo kimg -p deny
  ```

* All access is allowed:
  ```bash
  sudo kimg -p none
  ```

* Restrict mode, access is allowed only for processes in the initial mnt namespace:
  ```bash
  sudo kimg
  sudo kimg -p restrict
  ```

* Restrict mode, disable all direct and indirect access, but allow only bpf writes to user RAM from processes in the initial mnt namespace:
  ```bash
  sudo kimg -p restrict -a bpf_write
  ``` 

* Restrict mode, disable all and allow debugfs, ioport and unsigned module loading from processes in the initial mnt namespace: 
  ```bash
  sudo kimg -p restrict -a debugfs,ioport,unsigned_module
  ``` 

To disable this program delete the pinned file `/sys/fs/bpf/bpflock/kimg`. Re-executing will enable it again.


#### 3.1.2 Kernel modules protections

kmodules - implements restrictions to control module load and unload operations on modular kernels. It will allow to restrict or block access to:

  - Explicit module loading.
  - Loading of unsigned modules.
  - Automatic loading of kernel modules. This will block users (or attackers) from auto-loading modules. Unprivileged code will not be able to load "vulnerable" modules in this case. 
  - Unsafe usage of module parameters.


#### 3.1.4 BPF protection

disablebpf implements access restrictions on bpf syscall.

It supports following options:

 * Permission:
    - `allow|none`: bpf is allowed.
    - `deny`: bpf syscall and all its commands are denied for all processes on the system.
    - `restrict`: bpf is allowed only from processes that are in the initial mnt namespace. This allows systemd or container managers to properly use bpf. Default value.

 * Command to allow in case permission is `restrict`:
    - `bpf_write`: allow bpf_probe_write_user() helper that can be used to override user space memory. By default it is blocked.

 * Comma-separated list of commands to block in case permission is `restrict` or `allow`:
    - `map_create`: block creation of bpf maps.
    - `btf_load`: block loading BPF Type Format (BTF) metadata into the kernel.
    - `prog_load`: block loading bpf programs.
    - All other commands are allowed by default.
    
    If the list of commands to block is not set, then all bpf commands are allowed.

Examples:

* Deny BPF for all processes:
  ```bash
  sudo disablebpf -p deny
  ```

* BPF access is allowed:
  ```bash
  sudo disablebpf -p none
  ```

* Restrict mode, BPF access is allowed from processes in the initial mnt namespace:
  ```bash
  sudo disablebpf
  sudo disablebpf -p restrict
  ```

* Restrict mode, BPF access is allowed only from processes in the initial mnt namespace, but the `btf_load` loading BTF metadata into the kernel is blocked:
  ```bash
  sudo disablebpf -p restrict -b btf_load
  ```

* Restrict mode, BPF access is allowed only from processes in the initial mnt namespace. The bpf_probe_write_user() helper to write user RAM is also explicitly allowed from the initial mnt namespace only:
  ```bash
  sudo disablebpf -p restrict -a bpf_write
  ```

Make sure to execute this program last during boot and after all necessary bpf programs have been loaded. For containers workload to disable this program, delete the pinned file `/sys/fs/bpf/bpflock/disable-bpf`. Re-executing will enable it again.


### 3.2 Filesystem protections

To be added.


### 3.3 Namespaces protections

To be added.


## 4. Build and Dependencies


### 4.1 libbpf as git-submodule

This repository uses libbpf as a git-submodule. After cloning this repository you need to run the command:

```bash
git submodule update --init
```

If you want submodules to be part of the clone, you can use this command:

```bash
git clone --recurse-submodules https://github.com/linux-lock/bpflock
```

### 4.2 kernel

Tested on a kernel +5.11 with the following options:

```code
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBES=y
CONFIG_LSM="...,bpf"
CONFIG_BPF_LSM=y
```

### 4.3 Other dependencies

* Ubuntu
  ```bash
   sudo apt install -y bison build-essential flex git \
        libllvm7 llvm-7-dev libclang-7-dev zlib1g-dev \
        libelf-dev libfl-dev
  ```


### 4.4 Build

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