# Memory Protections

## Sections

  - [Kernel Image Lock-down](https://github.com/linux-lock/bpflock/blob/main/docs/memory-protections.md#1-kernel-image-lock-down)
  - [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protection)
  - [BPF Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection)

## 1. Kernel Image Lock-down

### 1.1 Introduction

`kimglock` - kernel image lock implements restrictions to
prevent both direct and indirect modification to a running
kernel image, attempting to protect against unauthorized access.
It combines the several Linux features including [kernel lockdown](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) and other LSMs to restrict
unauthorized modification of the kernel image at runtime.

After pinning the corresponding bpf program, kimglock will exit.

**Note: restrictions and protections are still a moving target, since the Linux kernel offer multiple access entries to modify the running image, it is hard to track all of them, however they will be added as they are discovered.**

kimglock is able to completely block or allow access from the
in the initial [pid namespace](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html) only to the following:

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


### 1.2 kimglock usage

`kimglock` supports the following options:

* `profile`:
  - `allow|none|privileged`: kernel image access is logged and allowed. Default profile.
  - `baseline` : restrictive profile where access is denied for all processes, except privileged applications and containers that run in the host pid and network namespaces, or applications that are present in the allow `bpflock_cgroupmap`.
  - `restricted`: direct and indirect access to a running kernel image is denied for all processes and containers.
 
* In case the profile is `allow` or `baseline`, a comma-separated list of operations to block can be specified:
  - `unsigned_module` : block unsigned module loading.
  - `unsafe_module_parameters` : block module with parameters that directly specify hardware
        parameters to drivers 
  - `dev_mem` : access to /dev/{mem,kmem,port} is blocked.
  - `kexec` : kexec of unsigned images is blocked.
  - `hibernation` : hibernation is blocked.
  - `pci_access` : block direct PCI BAR access.
  - `ioport` : raw io port access is blocked.
  - `msr` : raw msr access is blocked.
  - `mmiotrace` : tracing memory mapped I/O is blocked.
  - `debugfs` : debugfs is blocked.
  - `xmon_rw` : xmon write access is blocked.
  - `bpf_write` : block bpf write to user RAM .


`kimglock` examples:

* Allow profile: kernel image access is allowed.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```
  
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KIMGLOCK_PROFILE=allow" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: access is allowed only for processes in the initial pid and network namespaces.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KIMGLOCK_PROFILE=baseline" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: access is allowed only for processes in the initial pid and network namespaces, but debugfs, raw I/O port and loading of unsigned modules operations are blocked.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KIMGLOCK_PROFILE=baseline" \
    -e "BPFLOCK_KIMGLOCK_BLOCK=debugfs,ioport,unsigned_module" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: access is allowed only for processes in the initial pid and network namespaces, but the bpf writes to user RAM operation is denied for all.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KIMGLOCK_PROFILE=baseline" \
    -e "BPFLOCK_KIMGLOCK_BLOCK=bpf_write" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Restricted profile: direct and indirect access to a running kernel image is denied for all processes.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KIMGLOCK_PROFILE=restricted" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

### 1.3 Disable kimglock

To disable this program delete the directory `/sys/fs/bpf/bpflock/kimglock` and all its pinned content.

If `/sys` is read-only and can not be remounted, then `kimglock` is pinned and continues to run.


## 2 Kernel Modules Protection

### 2.1 Introduction

`kmodlock` implements restrictions to control module load operations on modular kernels. It allows to restrict or block access to:

  - Explicit module loading.
  - Loading of unsigned modules.
  - Automatic loading of kernel modules. This will block users (or attackers) from auto-loading modules. Unprivileged code will not be able to load "vulnerable" modules in this case. 
  - Unsafe usage of module parameters.

After pinning the corresponding bpf program, kmodlock will exit.

### 2.2 Modules protection usage

kmodlock supports the following options:

* `profile`: this is the global profile that takes one of the followings:
  - `allow|none|privileged` : they are the same, they define the least secure profile. In this profile access is logged and allowed for all processes. Useful to log security events.
  - `baseline` : restrictive profile where access is denied for all processes, except privileged applications and containers that run in the host pid and network namespaces, or applications that are present in the allow `bpflock_cgroupmap`.
  - `restricted` : heavily restricted profile where access is denied for all processes.

* In case the profile is `allow` or `baseline`, a comma-separated list of operations to block can be specified:
  - `load_module`: block module loading.
  - `autoload_module`: block automatic module loading.
  - `unsigned_module` : block unsigned module loading.
  - `unsafe_module_parameters` : block module parameters that directly specify hardware.
        parameters to drivers.

  If the list of operations to block is not set, then all operations are allowed according to the permission model.

Examples:

* Allow profile: loading kernel modules is logged and allowed.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```
  
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KMODLOCK_PROFILE=allow" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Allow profile: loading kernel modules is allowed, but unsigned modules and automatic modules loading are rejected.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KMODLOCK_PROFILE=allow" \
    -e "BPFLOCK_KMODLOCK_BLOCK=unsigned_module,autoload_module" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ``` 

* Baseline profile: module operations are allowed only from processes in the initial pid and network namespaces.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KMODLOCK_PROFILE=baseline" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: module operations are allowed only from processes in the initial pid and network namespaces, but loading unsigned modules and automatic operations are blocked for all.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KMODLOCK_PROFILE=baseline" \
    -e "BPFLOCK_KMODLOCK_BLOCK=unsigned_module,autoload_module" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Restriced profile: loading modules is denied or all processes.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_KMODLOCK_PROFILE=restricted" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

### 2.3 Disable modules protections

To disable this program, delete the directory `/sys/fs/bpf/bpflock/kmodlock` and all its pinned content. Re-executing will enable it again.

If `/sys` is read-only and can not be remounted, then bpflock kmodlock is pinned and continues to run.

## 3 BPF protection

### 3.1 Introduction

`bpfrestrict` - implements access restrictions on [bpf() syscall](https://man7.org/linux/man-pages/man2/bpf.2.html) by
restricting or blocking access to:

  - Loading BPF programs.
  - Creation of BPF maps.
  - Loading BPF Type Format (BTF) metadata into the kernel.
  - BPF writes to user RAM.

Make sure to execute this program last during boot and after all necessary bpf programs have been loaded. The list of blocked operations can be expended in future. After pinning the corresponding bpf program, bpfrestrict will exit.

### 3.2 bpfrestrict usage

It supports following options:

* `profile`: this is the global profile that takes one of the followings:
  - `allow|none|privileged` : they are the same, they define the least secure profile. In this profile access is logged and allowed for all processes. Useful to log security events.
  - `baseline` : restrictive profile where access is denied for all processes, except applications and containers that run in the host pid and network namespaces, or applications that are present in the allow `bpflock_cgroupmap`.
  - `restricted` : heavily restricted profile where access is denied for all processes.

* Comma-separated list of commands to block in case profile is `allow` or `baseline`:
  - `bpf_write`: block `bpf_probe_write_user()` that is used to write to user space memory.
  - `btf_load`: block loading BPF Type Format (BTF) metadata into the kernel.
  - `map_create`: block creation of bpf maps.
  - `prog_load`: block loading bpf programs.
  - All other commands are allowed by default.
    
  If the list of commands to block is not set, then all bpf commands are allowed.

Examples:

* Allow profile: BPF access is logged and allowed
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_BPFRESTRICT_PROFILE=allow" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Allow profile: BPF access is allowed but bpf write to user space memory is blocked for all.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_BPFRESTRICT_PROFILE=allow" \
    -e "BPFLOCK_BPFRESTRICT_BLOCK=bpf_write" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ``` 

* Baseline profile: BPF access is allowed from processes in the initial pid and network namespaces.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_BPFRESTRICT_PROFILE=baseline" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: BPF access is allowed only from processes in the initial pid and network namespaces, but bpf_probe_write_user() helper to write user RAM is blocked for all.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_BPFRESTRICT_PROFILE=baseline" \
    -e "BPFLOCK_BPFRESTRICT_BLOCK=bpf_write" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Baseline profile: BPF access is allowed only from processes in the initial pid and network namespaces, but the `btf_load` loading BTF metadata into the kernel is blocked for all.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_BPFRESTRICT_PROFILE=baseline" \
    -e "BPFLOCK_BPFRESTRICT_BLOCK=btf_load" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Restricted profile: deny BPF for all processes.
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
    -e "BPFLOCK_BPFRESTRICT_PROFILE=restricted" \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

### 3.3 Disable bpfrestrict

To disable bpfrestrict delete the directory `/sys/fs/bpf/bpflock/bpfrestrict` and all its pinned content. Re-executing will enable it again.

If `/sys` filesystem is read-only and can not be remounted read-write, then bpflock bpfrestrict is pinned and can't be disabled.
