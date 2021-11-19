# Memory Protections

## Sections

  1. [Kernel image lock-down](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#1-kernel-image-lock-down)
  2. [Kernel modules protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protections)
  3. [BPF protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection)
  4. [Execution of Memory ELF binaries](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#4-execution-of-memory-elf-binaries)


## 1. Kernel Image lock-down

### 1.1 Introduction

`kimgban` - kernel image ban implements restrictions to prevent both direct and indirect modification to a running kernel image, attempting to protect against unauthorized access. It combines the [kernel lockdown](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) features and other Linux Security Module features to protect against unauthorized modification of the kernel image.

**Note: this is still a moving target. Options are not stable**.

By default `kimgban` will restrict access to the following features and allow it only from processes in the initial [mnt namespace](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html):

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
  - BPF writes to user RAM.
  - Loading BPF Type Format (BTF) metadata into the kernel.


### 1.2 kimgban usage

`kimgban` supports the following options:

 * Permission:
    - allow|none: kernel image access is allowed.
    - deny: direct and indirect access to a running kernel image is denied for all processes and containers.
    - restrict: access is allowed only from processes that are in the initial mnt namespace. This allows, init programs, systemd and container managers to
    properly setup the working environment and communicate with the correspondig hardware. Default permission. 

 * Blocked access:
   If in restrict mode, then the kernel image lock-down will be enforced for all processes that are not in the initial mnt namespace, and [kernel features](https://github.com/linux-lock/bpflock/tree/main/memory-protections#11-introduction) to modify the running kernel are blocked.

 * Special access exceptions:
   If running under `restrict` permission model, then a coma-separated list of allowed features for the rest of all processes that are not in the initial mnt namespace can be specified:
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
   - `btf_load` : loading BPF Type Format (BTF) metadata into the kernel is allowed.


`kimgban` examples:

* Deny direct and indirect access to a running kernel image for all processes:
  ```bash
  sudo kimgban -p deny
  ```

* kernel image access is allowed:
  ```bash
  sudo kimgban -p none
  ```

* Restrict mode, access is allowed only for processes in the initial mnt namespace:
  ```bash
  sudo kimgban
  sudo kimgban -p restrict
  ```

* Restrict mode, access is allowed only for processes in the initial mnt namespace. Access from all other processes is denied, with an exception to allow only the bpf writes to user RAM operation:

  ```bash
  sudo kimgban -p restrict -a bpf_write
  ``` 

* Restrict mode, access is allowed only for processes in the initial mnt namespace, Access from all other processes is denied, with exceptions to access debugfs, raw I/O port and loading of unsigned modules operations:
  ```bash
  sudo kimgban -p restrict \
    -a debugfs,ioport,unsigned_module
  ``` 

### 1.3 Disable kimgban

To disable this program delete the directory `/sys/fs/bpf/bpflock/kimgban` and all its pinned content. Re-executing will enable it again.

If `/sys` is read-only and can not be remounted, then `kimgban` is pinned and continues to run.


## 2 Kernel Modules Protections

### 2.1 Introduction

`kmodban` implements restrictions to control module load operations on modular kernels. It allows to restrict or block access to:

  - Explicit module loading.
  - Loading of unsigned modules.
  - Automatic loading of kernel modules. This will block users (or attackers) from auto-loading modules. Unprivileged code will not be able to load "vulnerable" modules in this case. 
  - Unsafe usage of module parameters.

`kmodban` can also be used to ensure that all kernel modules, firmware, etc that are loaded originate from the same root filesystem. Extra flags can be passed to ensure that such filesystem is: mounted read-only or either backed by a read-only device such as dm-verity, if not then the operation will be denied. Some of this functionality was inspired by [LoadPin LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/LoadPin.html).

**Limitations: due to being an BPF program, it can miss some modules that have already been loaded before the bpf filesystem is mounted or the BPF program is inserted. Running this in early boot will minimize such cases.**

### 2.2 Modules protection usage

`kmodban` supports the following options:

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
  sudo kmodban -p deny
  ```

* Allow load and unload of kernel modules:
  ```bash
  sudo kmodban -p none
  ```

* Restrict mode, module operations are allowed only from processes in the initial mnt namespace:
  ```bash
  sudo kmodban
  sudo kmodban -p restrict
  ```

* Restrict mode, module operations are allowed only from processes in the initial mnt namespace, but loading of unsigned modules is blocked:
  ```bash
  sudo kmodban -p restrict -b unsigned_module
  ```

* Restrict mode, module operations are allowed only from processes in the initial mnt namespace, but automatic module loading is blocked for all:
  ```bash
  sudo kmodban -p restrict -b autoload_module
  ```

### 2.3 Disable modules protections

For containers workload to disable this program, delete the directory `/sys/fs/bpf/bpflock/kmodban` and all its pinned content. Re-executing will enable it again.

If `/sys` is read-only and can not be remounted, then `kmodban` is pinned and continues to run.


## 3 BPF protection

### 3.1 Introduction

`bpfban` - implements access restrictions on [bpf syscall](https://man7.org/linux/man-pages/man2/bpf.2.html) by restricting and blocking access to:

  - Loading BPF programs.
  - Creation of BPF maps.
  - Loading BPF Type Format (BTF) metadata into the kernel.
  - BPF writes to user RAM.

The list of blocked operations can be expended in future.


### 3.2 bpfban usage

It supports following options:

 * Permission:
    - `allow|none`: bpf is allowed.
    - `deny`: bpf syscall and all its commands are denied for all processes on the system.
    - `restrict`: bpf is allowed only from processes that are in the initial mnt namespace. This allows init, systemd or container managers to properly set up bpf. Default value.

 * Comma-separated list of commands to block in case permission is `restrict` or `allow`:
    - `bpf_write`: block `bpf_probe_write_user()` that is used to write to user space memory.
    - `btf_load`: block loading BPF Type Format (BTF) metadata into the kernel.
    - `map_create`: block creation of bpf maps.
    - `prog_load`: block loading bpf programs.
    - All other commands are allowed by default.
    
    If the list of commands to block is not set, then all bpf commands are allowed.

Examples:

* Deny BPF for all processes:
  ```bash
  sudo bpfban -p deny
  ```

* BPF access is allowed:
  ```bash
  sudo bpfban -p none
  ```

* Restrict mode, BPF access is allowed from processes in the initial mnt namespace:
  ```bash
  sudo bpfban
  sudo bpfban -p restrict
  ```

* Restrict mode, BPF access is allowed only from processes in the initial mnt namespace, but the `btf_load` loading BTF metadata into the kernel is blocked:
  ```bash
  sudo bpfban -p restrict -b btf_load
  ```

* Restrict mode, BPF access is allowed only from processes in the initial mnt namespace, but bpf_probe_write_user() helper to write user RAM is blocked:
  ```bash
  sudo bpfban -p restrict -b bpf_write
  ```

### 3.3 Disable bpfban

Make sure to execute this program last during boot and after all necessary bpf programs have been loaded. For containers workload to disable this program, delete the directory `/sys/fs/bpf/bpflock/bpfban` and all its pinned content. Re-executing will enable it again.

If `/sys` is read-only and can not be remounted, then `bpfban` is pinned and continues to run.