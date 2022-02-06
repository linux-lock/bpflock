# bpflock - Lock Linux machines

![Bpflock Logo](docs/images/bpflock-logo-small.png)

bpflock - eBPF driven security for locking and auditing Linux machines.

Note: bpflock is currently in **experimental stage**, it may break, options and security semantics may change, some BPF programs will be updated to use [Cilium ebpf library](https://github.com/cilium/ebpf/).

## Sections

* [1. Introduction](https://github.com/linux-lock/bpflock#1-introduction)
* [2. Functionality Overview](https://github.com/linux-lock/bpflock#2-functionality-overview)
  - [2.1 Security features](https://github.com/linux-lock/bpflock#21-security-features)
  - [2.2 Semantics](https://github.com/linux-lock/bpflock#12-semantics)
* [3. Deployment](https://github.com/linux-lock/bpflock#2-deployment)
* [4. Documentation](https://github.com/linux-lock/bpflock#3-documentation)
* [5. Build](https://github.com/linux-lock/bpflock#3-build)

## 1. Introduction

bpflock uses [eBPF](https://ebpf.io/) to strength Linux security. By restricting access to a various range of Linux features, bpflock is able to reduce the attack surface and block some well known attack techniques.

Only programs like container managers, systemd and other containers/programs that run in the host [pid and network namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html) are allowed access to full
Linux features, containers and applications that run on their own namespace will be restricted.
If bpflock bpf programs run under the `restricted` profile then all programs/containers including privileged
ones will have their access denied.

bpflock protects Linux machines by taking advantage of multiple security features including [Linux Security Modules + BPF](https://docs.kernel.org/bpf/prog_lsm.html).

Architecture and Security design notes:
- bpflock is not a mandatory access control labeling solution, and it does not intent to replace
[AppArmor](https://apparmor.net/), [SELinux](https://github.com/SELinuxProject/selinux), and other MAC solutions.
bpflock uses a simple declarative security profile.
- bpflock offers multiple small bpf programs that can be reused in multiple contexts from Cloud Native deployments to Linux IoT devices.
- bpflock is able to restrict root from accessing certain Linux features, however it does not protect against evil root.

## 2. Functionality Overview

### 2.1 Security features

bpflock offer multiple security protections that can be classified as:

* [Memory Protections](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md)
  - [Kernel Image Lock-down](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#1-kernel-image-lock-down)
  - [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protection)
  - [BPF Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection)

* [Process Protections](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md)
  - [Fileless Memory Execution](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md#fileless-memory-execution)
  - Namespaces protection

* [Hardware Addition Attacks](https://github.com/linux-lock/bpflock/tree/main/docs/hardware-additions.md)
  - [USB Additions Protection](https://github.com/linux-lock/bpflock/tree/main/docs/hardware-additions.md#1-usb-additions-protection)

* [System and Application tracing](https://github.com/linux-lock/bpflock/tree/main/docs/system-and-application-tracing.md)
  - [Trace Application Execution](https://github.com/linux-lock/bpflock/tree/main/docs/system-and-application-tracing.md#trace-application-execution)
  - Trace Privileged System Operations

* Filesystem Protections
  - Read-only root filesystem protection
  - sysfs protection

* Network protections

  - bpflock may include in future a simple network protection that can be used in single machine workload or Linux-IoT, but will not include a Cloud Native protection. [Cilium](https://github.com/cilium/cilium) and other kubernetes CNI related solutions are by far better.

### 2.2 Semantics

bpflock keeps the security semantics simple. It support three **global** profiles to broadly cover the security sepctrum, and restrict access to specific Linux features.

* `profile`: this is the global profile that can be applied per bpf program, it takes one of the followings:
  - `allow|none|privileged` : they are the same, they define the least secure profile. In this profile access is logged and allowed for all processes. Useful to log security events.
  - `baseline` : restrictive profile where access is denied for all processes, except privileged applications and containers that run in the host namespaces, or per cgroup allowed profiles in the `bpflock_cgroupmap` bpf map.
  - `restricted` : heavily restricted profile where access is denied for all processes.

* `Allowed` or `blocked` operations/commands:

  Under the `allow|privileged` or `baseline` profiles, a list of allowed or blocked commands can be specified and will be applied.
  - `--protection-allow` : comma-separated list of allowed operations. Valid under `baseline` profile, this is useful for applications that are too specific and perform privileged operations. It will reduce the use of the `allow | privileged` profile, so instead of using the `privileged` profile, we can specify the `baseline` one and add a set of allowed commands to offer a case-by-case definition for such applications.
  - `--protection-block` : comma-separated list of blocked operations. Valid under `allow|privileged` and `baseline` profiles, it allows to restrict access to some features without using the full `restricted` profile that might break some specific applications. Using `baseline` or `privileged` profiles opens the gate to access most Linux features, but with the `--protection-block` option some of this access can be blocked.

For bpf security examples check [bpflock configuration examples](https://github.com/linux-lock/bpflock/tree/main/deploy/configs/)


## 3. Deployment

### 3.1 Prerequisites

bpflock needs the following:

* Linux kernel version >= 5.13 with the following configuration:

  ```code
  CONFIG_BPF_SYSCALL=y
  CONFIG_DEBUG_INFO=y
  CONFIG_DEBUG_INFO_BTF=y
  CONFIG_KPROBES=y
  CONFIG_LSM="...,bpf"
  CONFIG_BPF_LSM=y
  ```

* Obviously a BTF enabled kernel.

#### Enable BPF LSM support

If your kernel was compiled with `CONFIG_BPF_LSM=y` check the `/boot/config-*` to confirm, but when running bpflock it fails with:

```
must have a kernel with 'CONFIG_BPF_LSM=y' 'CONFIG_LSM=\"...,bpf\"'"
```

Then to enable BPF LSM as an example on Ubuntu:

  1. Open the /etc/default/grub file as privileged of course.
  2. Append the following to the `GRUB_CMDLINE_LINUX` variable and save.
     ```
     "lsm=lockdown,capability,yama,apparmor,bpf"
     ```
     or
     ```
     GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,apparmor,bpf"
     ```
  3. Update grub config with:
     ```bash
     sudo update-grub2
     ```
  4. Reboot into your kernel.


### 3.2 Docker deployment

To run using the default `allow` or `privileged` profile (the least secure profile):
```bash
docker run --name bpflock -it --rm --cgroupns=host \
  --pid=host --privileged \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

#### Fileless Binary Execution

To log and restict [fileless binary execution](https://github.com/linux-lock/bpflock/tree/main/docs/process-protections.md#fileless-memory-execution) run with:

```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_FILELESSLOCK_PROFILE=restricted" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

When running under `restricted` profile, the container logs will display:
```
time="2022-02-04T14:54:33Z" level=info msg="event=syscall_execve tgid=1833 pid=1833 ppid=1671 uid=1000 cgroupid=8821 comm=loader pcomm=bash filename=./loader retval=0" bpfprog=execsnoop subsys=bpf

time="2022-02-04T14:54:33Z" level=info msg="event=lsm_bprm_creds_from_file tgid=1833 pid=1833 ppid=1671 uid=1000 cgroupid=8821 comm=loader pcomm=bash filename=memfd:memfd-test retval=-1 reason=denied (restricted)" bpfprog=filelesslock subsys=bpf

time="2022-02-04T14:54:33Z" level=info msg="event=syscall_execve tgid=1833 pid=1833 ppid=0 uid=1000 cgroupid=8821 comm= pcomm= filename=/proc/self/fd/3 retval=-1" bpfprog=execsnoop subsys=bpf
```

Running under the `restricted` profile may break things, this is why the default profile is `allow`.

#### Kernel Modules Protection

To apply [Kernel Modules Protection](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#2-kernel-modules-protection)
run with environment variable `BPFLOCK_KMODLOCK_PROFILE=baseline` or `BPFLOCK_KMODLOCK_PROFILE=restricted`:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_KMODLOCK_PROFILE=baseline" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

Example:
```bash
$ sudo unshare -f -p bash
# modprobe xfs
modprobe: ERROR: could not insert 'xfs': Operation not permitted
```

```
modprobe-399022  [002] d...1 427205.192790: bpf_trace_printk: bpflock bpf=kmodlock pid=399022 event=module load from non init pid namespace status=denied (baseline)
```

#### Kernel Image Lock-down

To apply [Kernel Image Lock-down](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#1-kernel-image-lock-down) run with environment variable `BPFLOCK_KIMGLOCK_PROFILE=baseline` or `BPFLOCK_KIMGLOCK_PROFILE=restricted`:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_KIMGLOCK_PROFILE=baseline" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

#### BPF Protection

To apply [bpf restriction](https://github.com/linux-lock/bpflock/tree/main/docs/memory-protections.md#3-bpf-protection) run with environment variable `BPFLOCK_BPFRESTRICT_PROFILE=baseline` or `BPFLOCK_BPFRESTRICT_PROFILE=restricted`:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -e "BPFLOCK_BPFRESTRICT_PROFILE=baseline" \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

Example running in a different pid and network namespaces and using [bpftool](https://github.com/libbpf/bpftool):
```bash
$ sudo unshare -f -p -n bash
# bpftool prog
Error: can't get next program: Operation not permitted
```

Example output of denied operation failed with -1 -EPERM:
```
time="2022-02-04T15:40:56Z" level=info msg="event=lsm_bpf tgid=2378 pid=2378 ppid=2364 uid=0 cgroupid=9458 comm=bpftool pcomm=bash filename= retval=-1 reason=baseline" bpfprog=bpfrestrict subsys=bpf

time="2022-02-04T15:40:56Z" level=info msg="event=lsm_bpf tgid=2378 pid=2378 ppid=2364 uid=0 cgroupid=9458 comm=bpftool pcomm=bash filename= retval=-1 reason=baseline" bpfprog=bpfrestrict subsys=bpf
```

Running with the `-e "BPFLOCK_BPFRESTRICT_PROFILE=restricted"` profile will deny bpf for all:
```
time="2022-02-04T15:44:13Z" level=info msg="event=syscall_execve tgid=2500 pid=2500 ppid=2499 uid=0 cgroupid=9458 comm=bpftool pcomm=sudo filename=./tools/amd64/bpftool retval=0" bpfprog=execsnoop subsys=bpf

time="2022-02-04T15:44:13Z" level=info msg="event=lsm_bpf tgid=2500 pid=2500 ppid=2499 uid=0 cgroupid=9458 comm=bpftool pcomm=sudo filename= retval=-1 reason=denied (restricted)" bpfprog=bpfrestrict subsys=bpf

time="2022-02-04T15:44:13Z" level=info msg="event=lsm_bpf tgid=2500 pid=2500 ppid=2499 uid=0 cgroupid=9458 comm=bpftool pcomm=sudo filename= retval=-1 reason=denied (restricted)" bpfprog=bpfrestrict subsys=bpf
```

### 3.3 Configuration and Environment file

Passing configuration as bind mounts can be achieved using the following command.

Assuming [bpflock.yaml](https://github.com/linux-lock/bpflock/blob/main/deploy/configs/bpflock/bpflock.yaml) and [bpf.d profiles](https://github.com/linux-lock/bpflock/blob/main/deploy/configs/bpflock/bpf.d/) configs are in current directory inside `bpflock` directory, then we can just use:

```bash
ls bpflock/
  bpf.d  bpflock.d  bpflock.yaml
```
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  -v $(pwd)/bpflock/:/etc/bpflock \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

Passing environment variables can also be done with files using `--env-file`. All parameters can be passed as environment variables using the `BPFLOCK_$VARIABLE_NAME=VALUE` format.

Example run with environment variables in a file:
```bash
docker run --name bpflock -it --rm --cgroupns=host --pid=host --privileged \
  --env-file bpflock.env.list \
  -v /sys/kernel/:/sys/kernel/ \
  -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
```

## 4. Documentation

Documentation files can be found [here](https://github.com/linux-lock/bpflock/tree/main/docs/).

## 5. Build

bpflock uses [docker BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/) to build and
[Golang](https://go.dev/doc/install) to make some checks and run tests. bpflock is built inside Ubuntu container that
downloads the standard golang package.

Run the following to build the bpflock docker container:
```bash
git submodule update --init --recursive
make
```

Bpf programs are built using libbpf. The docker image used is Ubuntu.

If you want to only build the bpf programs directly without using docker, then on Ubuntu:
```bash
sudo apt install -y pkg-config bison binutils-dev build-essential \
        flex libc6-dev clang-12 libllvm12 llvm-12-dev libclang-12-dev \
        zlib1g-dev libelf-dev libfl-dev gcc-multilib zlib1g-dev \
        libcap-dev libiberty-dev libbfd-dev
```

Then run:
```bash
make bpf-programs
```

In this case the generated programs will be inside the ./bpf/build/... directory.

## Credits

bpflock uses lot of resources including source code from the [Cilium](https://github.com/cilium/cilium) and
[bcc](https://github.com/iovisor/bcc) projects.

## License

The bpflock user space components are licensed under the [Apache License, Version 2.0](https://github.com/linux-lock/bpflock/blob/main/LICENSE). The BPF code where it is noted is licensed under the [General Public License, Version 2.0](https://github.com/linux-lock/bpflock/blob/main/src/COPYING).
