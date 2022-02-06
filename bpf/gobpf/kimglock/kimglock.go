// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Djalal Harouni

package kimglock

import (
	"fmt"

	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"
)

const (
	LOCK_KIMG_NONE = iota
	LOCK_KIMG_MODULE_SIGNATURE
	LOCK_KIMG_DEV_MEM
	LOCK_KIMG_EFI_TEST
	LOCK_KIMG_KEXEC
	LOCK_KIMG_HIBERNATION
	LOCK_KIMG_PCI_ACCESS
	LOCK_KIMG_IOPORT
	LOCK_KIMG_MSR
	LOCK_KIMG_ACPI_TABLES
	LOCK_KIMG_PCMCIA_CIS
	LOCK_KIMG_TIOCSSERIAL
	LOCK_KIMG_MODULE_PARAMETERS
	LOCK_KIMG_MMIOTRACE
	LOCK_KIMG_DEBUGFS
	LOCK_KIMG_XMON_WR
	LOCK_KIMG_BPF_WRITE_USER
	LOCK_KIMG_INTEGRITY_MAX
	LOCK_KIMG_KCORE
	LOCK_KIMG_KPROBES
	LOCK_KIMG_BPF_READ_KERNEL
	LOCK_KIMG_PERF
	LOCK_KIMG_TRACEFS
	LOCK_KIMG_XMON_RW
	LOCK_KIMG_XFRM_SECRET
	LOCK_KIMG_CONFIDENTIALITY_MAX
)

func getKimgLockOp(operationId int32) string {
	if operationId > 0 && operationId <= LOCK_KIMG_CONFIDENTIALITY_MAX {
		/*
		 * From kernel source security/security.c
		 * These are descriptions of the reasons that can be passed to the
		 * security_locked_down() LSM hook. Placing this array here allows
		 * all security modules to use the same descriptions for auditing
		 * purposes.
		 */
		switch operationId {
		case LOCK_KIMG_NONE:
			return "none"
		case LOCK_KIMG_MODULE_SIGNATURE:
			return "unsigned module loading"
		case LOCK_KIMG_DEV_MEM:
			return "/dev/mem,kmem,port"
		case LOCK_KIMG_EFI_TEST:
			return "/dev/efi_test access"
		case LOCK_KIMG_KEXEC:
			return "kexec of unsigned images"
		case LOCK_KIMG_HIBERNATION:
			return "hibernation"
		case LOCK_KIMG_PCI_ACCESS:
			return "direct PCI access"
		case LOCK_KIMG_IOPORT:
			return "raw io port access"
		case LOCK_KIMG_MSR:
			return "raw MSR access"
		case LOCK_KIMG_ACPI_TABLES:
			return "modifying ACPI tables"
		case LOCK_KIMG_PCMCIA_CIS:
			return "direct PCMCIA CIS storage"
		case LOCK_KIMG_TIOCSSERIAL:
			return "reconfiguration of serial port IO"
		case LOCK_KIMG_MODULE_PARAMETERS:
			return "unsafe module parameters"
		case LOCK_KIMG_MMIOTRACE:
			return "unsafe mmio"
		case LOCK_KIMG_DEBUGFS:
			return "debugfs access"
		case LOCK_KIMG_XMON_WR:
			return "xmon write access"
		case LOCK_KIMG_BPF_WRITE_USER:
			return "use of bpf to write user RAM"
		case LOCK_KIMG_INTEGRITY_MAX:
			return "integrity"
		case LOCK_KIMG_KCORE:
			return "/proc/kcore access"
		case LOCK_KIMG_KPROBES:
			return "use of kprobes"
		case LOCK_KIMG_BPF_READ_KERNEL:
			return "use of bpf to read kernel RAM"
		case LOCK_KIMG_PERF:
			return "unsafe use of perf"
		case LOCK_KIMG_TRACEFS:
			return "use of tracefs"
		case LOCK_KIMG_XMON_RW:
			return "xmon read and write access"
		case LOCK_KIMG_XFRM_SECRET:
			return "xfrm SA secret"
		case LOCK_KIMG_CONFIDENTIALITY_MAX:
			return "confidentiality"
		}
	}

	return ""
}

func GetOperationStr(event *bpfevents.ProcessEvent) (string, error) {
	if event.ProgramId != bpfevents.KimgLockId &&
		event.EventId != bpfevents.LsmLockedDownId {
		return "", fmt.Errorf("not a kimglock operation")
	}

	op := getKimgLockOp(event.OperationId)
	if op == "" {
		op = "(none)"
	}

	return op, nil
}
