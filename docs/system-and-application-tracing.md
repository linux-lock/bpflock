# System and Application Tracing

## Sections

  - [Trace Application Execution](https://github.com/linux-lock/bpflock/tree/main/docs/system-and-application-tracing.md#trace-application-execution)

## Trace Application Execution

### Introduction

`execnoop` - Trace process exec() calls. It is derivered from the [execsnoop of the bcc
project](https://github.com/iovisor/bcc).

Combined with other bpf programs it allows to give more context about process execution.

### Usage

It supports following option:

 * `--exec-snoop`:
    - `none` : tracing process exec() calls is disabled.
    - `all` : trace all process exec() calls.

* Tracing process execution is disabled:
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host \
     --pid=host --privileged \
     -v /sys/kernel/:/sys/kernel/ \
     -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

* Trace all process execution:
  ```bash
  docker run --name bpflock -it --rm --cgroupns=host \
     --pid=host --privileged \
     -e "BPFLOCK_EXEC_SNOOP=all" \
     -v /sys/kernel/:/sys/kernel/ \
     -v /sys/fs/bpf:/sys/fs/bpf linuxlock/bpflock
  ```

### Disable execsnoop

To disable bpflock execsnoop, just stop the container. In future more options will be added to disable it without
stopping the bpflock container.