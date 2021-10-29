# `bpflock` - Lock Linux machines

`bpflock` - eBPF driven security for locking and auditing Linux machines.

#### This is a Work In Progress:

* `bpflock` is currently in experimental stage and some BPF programs are being updated.

* Programs will be updated soon to use [Cilium ebpf library](https://github.com/cilium/ebpf/) and turned into a small daemon.

## Sections

* [1. Introduction](https://github.com/linux-lock/bpflock#1-introduction)
  - [1.1 Security features](https://github.com/linux-lock/bpflock#11-security-features)
  - [1.2 Semantics](https://github.com/linux-lock/bpflock#12-semantics)
* [2. Build](https://github.com/linux-lock/bpflock#2-build)
* [3. Security protections](https://github.com/linux-lock/bpflock#3-security-protections)
  - [3.1 Hardware additions](https://github.com/linux-lock/bpflock#31-hardware-additions)
  - [3.2 Memory protections](https://github.com/linux-lock/bpflock#32-memory-protections)
  - [3.3 Filesystem protections](https://github.com/linux-lock/bpflock#33-filesystem-protections)
  - [3.4 Namespaces protections](https://github.com/linux-lock/bpflock#34-namespaces-protections)


## 1. Introduction

`bpflock` is designed to work along side, init programs, systemd or container managers to protect Linux machines using a system wide approach. The `"plan"` is to make it usable on kubernetes deployments, servers, Linux-IoT devices, and work stations.

`bpflock` combines multiple bpf independent programs to restrict access to a wide range of Linux features, only services like init, systemd or container managers that run in the initial [mnt namespace](https://man7.org/linux/man-pages/man7/namespaces.7.html) will be able to access all Linux kernel features, other tasks including containers that run on their own namespaces will be
restricted or completely blocked.

`bpflock` uses [LSM BPF](https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html) to implement its security features.

**Note: `bpflock` is able to restrict root access to some features, however it does not protect against evil root users. Such users are able to disable `bpflock` if `/sys` file system is writable.**


### 1.1 Security features

* [Hardware additions](https://github.com/linux-lock/bpflock#31-hardware-additions)

  - [usblock](https://github.com/linux-lock/bpflock#311-usb-additions-protection)

* [Memory protections](https://github.com/linux-lock/bpflock#32-memory-protections)

  - [Kernel image lock down](https://github.com/linux-lock/bpflock#321-kernel-image-lockdown)
  - [Kernel modules protection](https://github.com/linux-lock/bpflock#322-kernel-modules-protections)
  - [BPF protection](https://github.com/linux-lock/bpflock#323-bpf-protection)
  - [Execution of In-Memory-Only ELF binaries (memfd)](https://github.com/linux-lock/bpflock#324-execution-of-in-memory-only-elf-binaries)

* [Filesystem protections](https://github.com/linux-lock/bpflock#33-filesystem-protections)

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

Follow [build documentation](https://github.com/linux-lock/bpflock#4.4-build) on how to build it.


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

### 2.3 Other dependencies

* Ubuntu
  ```bash
  sudo apt install -y bison build-essential flex \
        git libllvm7 llvm-7-dev libclang-7-dev \
        zlib1g-dev libelf-dev libfl-dev
  ```

### 2.4 Build

Get libbpf if not:
```
git submodule update --init
```

To build just run:
```bash
make
```

All build binaries will be produced in `src/` directory.

Current build process was inspired by: https://github.com/iovisor/bcc/tree/master/libbpf-tools


## 3. Protections

### 3.1 Hardware additions

#### 3.1.1 USB additions protection

`usblock` - Implements restrictions to lock-down USB devices.
When connecting a USB device it will be shown on the system but not
authorized to be used, this allows to **restrict** some bad USB
and poisontap attacks that emulate an Ethernet device over USB to
hijack network traffic.

`usblock` supports blocking new USB devices at runtime without changing your
machine configuration.

**This is particulary useful if you do not trust the USB ports of your IoT
devices or servers, and have remote access where you control when to activate or deactivate those same USB interfaces.**

**Note: protecting machines from attackers
that have unlimited physicall access to perform different scenarios is a lost
case.**

### 3.2 Memory protections

#### 3.2.1 kernel image lockdown

`kimg` - kernel image implements restrictions to prevent both direct and indirect access to a running kernel image, attempting to protect against unauthorized modification. It combines the [kernel lockdown](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) features and other Linux Security Module hooks to protect against unauthorized modification of the kernel image.

**Note: this is still a moving target. Options are not stable**.

By default `kimg` will allow access to the following features only from processes in the initial [mnt namespace](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html):

  - Loading of unsigned modules.
  - Unsafe usage of module parameters.
  - Access to `/dev/mem, /dev/kmem and /dev/port`.
  - Access to `/dev/efi_test`.
  - kexec of unsigned images.
  - Hibernation of the machine.
  - Direct PCI access.
  - Raw io port access.
  - Raw MSR registers access for x86.
  - Modification of ACPI tables.
  - Direct PCMCIA CIS storage.
  - Reconfiguration of serial port IO.
  - Usage of the ioperm and iopl instructions on x86. 
  - Debugfs access.
  - xmon write access.
  - bpf writes to user RAM.


`kimg` supports the following options:

 * Permission:
    - allow|none: kernel image access is allowed.
    - deny: direct and indirect access to a running kernel image is denied for all processes and containers.
    - restrict: access is allowed only from processes that are in the initial mnt namespace. This allows, init programs, systemd and container managers to
    properly setup the working environment and communicate with the correspondig hardware. Default permission. 

 * Blocked access:
   If in restrict mode, then the integrity mode of kernel lock down will be enforced for all processes that are not in the initial mnt namespace, and [kernel features](https://github.com/linux-lock/bpflock#311-kernel-image-lockdown) to modify the running kernel are blocked.

 * Special access exceptions:
   If running under `restrict` permission model, then a coma-separated list of allowed features for the rest of processes that are not in the initial mnt namespace can be specified:
   - `unsigned_module` : allow unsigned module loading.
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

* Deny direct and indirect access to a running kernel image for all processes:
  ```bash
  sudo kimg -p deny
  ```

* kernel image access is allowed:
  ```bash
  sudo kimg -p none
  ```

* Restrict mode, access is allowed only for processes in the initial mnt namespace:
  ```bash
  sudo kimg
  sudo kimg -p restrict
  ```

* Restrict mode, access is allowed only for processes in the initial mnt namespace. Access from all other processes is denied, with an exception to allow only the bpf writes to user RAM operation:

  ```bash
  sudo kimg -p restrict -a bpf_write
  ``` 

* Restrict mode, access is allowed only for processes in the initial mnt namespace, Access from all other processes is denied, with exceptions to access debugfs, raw I/O port and loading of unsigned modules operations:
  ```bash
  sudo kimg -p restrict \
    -a debugfs,ioport,unsigned_module
  ``` 

To disable this program delete the directory `/sys/fs/bpf/bpflock/kimg` and all its pinned content. Re-executing will enable it again.


#### 3.2.2 Kernel modules protections

`disablemodules` implements restrictions to control module load operations on modular kernels. It allows to restrict or block access to:

  - Explicit module loading.
  - Loading of unsigned modules.
  - Automatic loading of kernel modules. This will block users (or attackers) from auto-loading modules. Unprivileged code will not be able to load "vulnerable" modules in this case. 
  - Unsafe usage of module parameters.

`disablemodules` can also be used to ensure that all kernel modules, firmware, etc that are loaded originate from the same root filesystem. Extra flags can be passed to ensure that such filesystem is: mounted read-only or either backed by a read-only device such as dm-verity, if not then the operation will be denied. Some of this functionality was inspired by [LoadPin LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/LoadPin.html).

**Limitations: due to being an BPF program, it can miss some modules that have already been loaded before the bpf filesystem is mounted or the BPF program is inserted. Running this in early boot will minimize such cases.**

`disablemodules` supports the following options:

 * Permission:
   - `allow|none`: load and unload module operations are allowed.
   - `deny`: all operations of loading and unloading modules are denied for all processes on the system.
   - `restrict`: load and unload modules are allowed only from processes that are in the initial mnt namespace. This allows init, systemd or container managers to properly set up the system. Default value.

 * Root filesystem options:
   - `--rootfs`: allow module operations only if the modules originate from the root filesystem.
   - `--ro`: allow module operations only if the root filesystem is mounted read-only.
   - `--ro-dev`: allow module operations only if the filesystem is backed by a read-only device.

 * In case permission model is `restrict` or `allow`, a comma-separated list of operations to block can be specified:
   - `load_module`: block module loading.
   - `autoload_module`: block automatic module loading.
   - `unsigned_module` : block unsigned module loading.
   - `unsafe_module_parameters` : block module parameters that directly specify hardware.
         parameters to drivers.

   If the list of operations to block is not set, then all operations are allowed according to the permission model.


Examples:

* Deny load and unload modules for all processes:
  ```bash
  sudo disablemodules -p deny
  ```

* Allow load and unload of kernel modules:
  ```bash
  sudo disablemodules -p none
  ```

* Restrict mode, module operations are allowed only from processes in the initial mnt namespace:
  ```bash
  sudo disablemodules
  sudo disablemodules -p restrict
  ```

* Restrict mode, module operations are allowed only from processes in the initial mnt namespace, but loading of unsigned modules is blocked:
  ```bash
  sudo disablebpf -p restrict -b unsigned_module
  ```

* Restrict mode, module operations are allowed only from processes in the initial mnt namespace, but automatic module loading is blocked for all:
  ```bash
  sudo disablebpf -p restrict -b autoload_module
  ```

For containers workload to disable this program, delete the directory `/sys/fs/bpf/bpflock/disable-modules` and all its pinned content. Re-executing will enable it again.


#### 3.2.3 BPF protection

`disablebpf` - implements access restrictions on [bpf syscall](https://man7.org/linux/man-pages/man2/bpf.2.html).

It supports following options:

 * Permission:
    - `allow|none`: bpf is allowed.
    - `deny`: bpf syscall and all its commands are denied for all processes on the system.
    - `restrict`: bpf is allowed only from processes that are in the initial mnt namespace. This allows init, systemd or container managers to properly set up bpf. Default value.

 * Comma-separated list of commands to block in case permission is `restrict` or `allow`:
    - `bpf_write`: block `bpf_probe_write_user()` helper that is used to write to user space memory.
    - `btf_load`: block loading BPF Type Format (BTF) metadata into the kernel.
    - `map_create`: block creation of bpf maps.
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

* Restrict mode, BPF access is allowed only from processes in the initial mnt namespace, but bpf_probe_write_user() helper to write user RAM is blocked:
  ```bash
  sudo disablebpf -p restrict -b bpf_write
  ```

Make sure to execute this program last during boot and after all necessary bpf programs have been loaded. For containers workload to disable this program, delete the directory `/sys/fs/bpf/bpflock/disable-bpf` and all its pinned content. Re-executing will enable it again.


### 3.3 Filesystem protections

To be added.


### 3.4 Namespaces protections

To be added.
