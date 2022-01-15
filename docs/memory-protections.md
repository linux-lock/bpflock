# Memory Protections

## Sections

  1. [Kernel Image Lock-down](https://github.com/linux-lock/bpflock/blob/main/docs/memory--profile=rotections.md#1-kernel-image-lock-down)
  2. [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory--profile=rotections.md#2-kernel-modules--profile=rotections)
  3. [BPF Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory--profile=rotections.md#3-bpf--profile=rotection)
  4. [Execution of Memory ELF binaries](https://github.com/linux-lock/bpflock/tree/main/docs/memory--profile=rotections.md#4-execution-of-memory-elf-binaries)


## 1. Kernel Image Lock-down

### 1.1 Introduction

`kimglock` - kernel image lock implements restrictions to prevent both direct and indirect modification to a running kernel image, attempting to protect against unauthorized access. It combines the [kernel lockdown](https://man7.org/linux/man--profile=ages/man7/kernel_lockdown.7.html) features and other Linux Security Module features to protect against unauthorized modification of the kernel image.

**Note: this is still a moving target. Options are not stable**.

By default `kimglock` will restrict access to the following features and allow it only from processes in the initial [pid namespace](https://man7.org/linux/man--profile=ages/man7/mount_namespaces.7.html):

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


### 1.2 kimglock usage

`kimglock` supports the following options:

 * profile:
    - allow|none|privileged: kernel image access is allowed. Default profile.
    - baseline: access is allowed only from processes that are in the initial pid namespace. This allows, init programs, systemd and container managers to properly setup the working environment and communicate with the correspondig hardware.
    - restricted: direct and indirect access to a running kernel image is denied for all processes and containers.
 
 * Blocked access:
   If in baseline profile, then the kernel image lock-down will be enforced for all processes that are not in the initial pid namespace, and [kernel features](https://github.com/linux-lock/bpflock/blob/main/docs/memory--profile=rotections.md#1-kernel-image-lock-down) to modify the running kernel are blocked. Special access exceptions can be set to allow some specific operations.

 * Baseline profile access exceptions:
   A coma-separated list of allowed features for the rest of all processes that are not in the initial pid namespace can be specified:
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


`kimglock` examples:

* Allow profile: kernel image access is allowed.
  ```bash
  sudo bpflock --kimglock-profile=none
  sudo bpflock --kimglock-profile=allow
  sudo bpflock --kimglock-profile=privileged
  ```

* Baseline profile: access is allowed only for processes in the initial pid namespace.
  ```bash
  sudo bpflock --kimglock-profile=baseline
  ```

* Baseline profile: access is allowed only for processes in the initial pid namespace. Access from all other processes is denied with exceptions to access debugfs, raw I/O port and loading of unsigned modules operations.
  ```bash
  sudo bpflock --kimglock-profile=baseline \
    --kimglock-allow=debugfs,ioport,unsigned_module
  ``` 

* Baseline profile: access is allowed only for processes in the initial pid namespace. Access from all other processes is denied with an exception to allow only the bpf writes to user RAM operation.

  ```bash
  sudo bpflock --kimglock-profile=baseline --kimglock-allow=bpf_write
  ``` 

* Restricted profile: direct and indirect access to a running kernel image is denied for all processes.
  ```bash
  sudo bpflock --kimglock-profile=restricted
  ```

### 1.3 Disable kimglock

To disable this program delete the directory `/sys/fs/bpf/bpflock/kimglock` and all its pinned content.

If `/sys` is read-only and can not be remounted, then `kimglock` is pinned and continues to run.


## 2 Kernel Modules Protections

### 2.1 Introduction

`kmodlock` implements restrictions to control module load operations on modular kernels. It allows to restrict or block access to:

  - Explicit module loading.
  - Loading of unsigned modules.
  - Automatic loading of kernel modules. This will block users (or attackers) from auto-loading modules. Unprivileged code will not be able to load "vulnerable" modules in this case. 
  - Unsafe usage of module parameters.

`kmodlock` can also be used to ensure that all kernel modules and firmware that are loaded originate from the same root filesystem. Extra flags can be passed to ensure that such filesystem is: mounted read-only or either backed by a read-only device such as dm-verity, if not then the operation will be denied. Some of this functionality was inspired by [LoadPin LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/LoadPin.html).


### 2.2 Modules protection usage

`kmodlock` supports the following options:

 * profile:
   - `allow|none|privileged`: load module operations are allowed. Default value.
   - `baseline`: load and unload modules are allowed only from processes that are in the initial pid namespace. This allows init, systemd or container managers to properly set up the system.
   - `restricted`: all operations of loading modules are denied for all processes on the system.

 * Root filesystem options:
   - `--kmodlock-rootfs`: allow module operations only if the modules originate from the root filesystem.
   - `--kmodlock-ro`: allow module operations only if the root filesystem is mounted read-only.
   - `--kmodlcok-ro-dev`: allow module operations only if the filesystem is backed by a read-only device.

 * In case the profile is `baseline`, a comma-separated list of operations to block can be specified:
   - `load_module`: block module loading.
   - `autoload_module`: block automatic module loading.
   - `unsigned_module` : block unsigned module loading.
   - `unsafe_module_parameters` : block module parameters that directly specify hardware.
         parameters to drivers.

   If the list of operations to block is not set, then all operations are allowed according to the permission model.


Examples:

* Allow profile: loading kernel modules is allowed.
  ```bash
  sudo bpflock --kmodlock-profile=allow
  sudo bpflock --kmodlock-profile=none
  sudo bpflock --kmodlock-profile=privileged
  ```

* Baseline profile: module operations are allowed only from processes in the initial pid namespace.
  ```bash
  sudo bpflock --kmodlock-profile=baseline
  ```

* Baseline profile: module operations are allowed only from processes in the initial pid namespace, but loading unsigned modules is blocked for all.
  ```bash
  sudo bpflock --kmodlock-profile=baseline --kmodlock-block=unsigned_module
  ```

* Baseline profile: module operations are allowed only from processes in the initial pid namespace, but automatic module loading is blocked for all.
  ```bash
  sudo bpflock --kmodlock-profile=baseline --kmodlock-block=autoload_module
  ```

* Restriced profile: load modules denied or all processes.
  ```bash
  sudo bpflock --kmodlock-profile=restricted
  ```

### 2.3 Disable modules protections

For containers workload to disable this program, delete the directory `/sys/fs/bpf/bpflock/kmodlock` and all its pinned content. Re-executing will enable it again.

If `/sys` is read-only and can not be remounted, then bpflock kmodlock is pinned and continues to run.


## 3 BPF protection

### 3.1 Introduction

`bpfrestrict` - implements access restrictions on [bpf syscall](https://man7.org/linux/man--profile=ages/man2/bpf.2.html) by
restricting or blocking access to:

  - Loading BPF programs.
  - Creation of BPF maps.
  - Loading BPF Type Format (BTF) metadata into the kernel.
  - BPF writes to user RAM.

Make sure to execute this program last during boot and after all necessary bpf programs have been loaded. The list of blocked operations can be expended in future.

### 3.2 bpfrestrict usage

It supports following options:

 * profile:
    - `allow|none|privileged`: bpf is allowed for all processes on the system.
    - `baseline`: bpf is allowed only from processes that are in the initial pid namespace. This allows container managers, systemd, init, etc to properly set up bpf.
    - `restricted`: bpf syscall and all its commands are denied for all processes on the system.

 * Comma-separated list of commands to block in case profile is `baseline`:
    - `bpf_write`: block `bpf_probe_write_user()` that is used to write to user space memory.
    - `btf_load`: block loading BPF Type Format (BTF) metadata into the kernel.
    - `map_create`: block creation of bpf maps.
    - `prog_load`: block loading bpf programs.
    - All other commands are allowed by default.
    
    If the list of commands to block is not set, then all bpf commands are allowed.

Examples:

* Allow profile: BPF access is allowed
  ```bash
  sudo bpflock --bpfrestrict-profile=none
  sudo bpflock --bpfrestrict-profile=allow
  sudo bpflock --bpfrestrict-profile=privileged
  ```

* Baseline profile: BPF access is allowed from processes in the initial pid namespace.
  ```bash
  sudo bpflock --bpfrestrict-profile=baseline
  ```

* Baseline profile: BPF access is allowed only from processes in the initial pid namespace, but bpf_probe_write_user() helper to write user RAM is blocked for all.
  ```bash
  sudo bpflock --bpfrestrict-profile=baseline --bpfrestrict-block=bpf_write
  ```

* Baseline profile: BPF access is allowed only from processes in the initial pid namespace, but the `btf_load` loading BTF metadata into the kernel is blocked.
  ```bash
  sudo bpflock --bpfrestrict-profile=baseline --bpfrestrict-block=btf_load
  ```

* Restricted profile: deny BPF for all processes.
  ```bash
  sudo bpflock --bpfrestrict-profile=restricted
  ```

### 3.3 Disable bpfrestrict

For containers workload to disable bpfrestrict, delete the directory `/sys/fs/bpf/bpflock/bpfrestrict` and all its pinned content. Re-executing will enable it again.

If `/sys` filesystem is read-only and can not be remounted read-write, then bpflock bpfrestrict is pinned and can't be disabled.
