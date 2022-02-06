// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Djalal Harouni

package kmodlock

import (
	"fmt"

	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"
)

const (
	BPFLOCK_KM_LOAD = 1 << iota
	BPFLOCK_KM_UNLOAD
	BPFLOCK_KM_AUTOLOAD
	BPFLOCK_KM_UNSIGNED
	BPFLOCK_KM_UNSAFEMOD
)

func getKmodLockOp(operationId int32) string {
	if operationId == 0 {
		return ""
	}

	id := int(operationId)
	if (id & BPFLOCK_KM_LOAD) != 0 {
		return "loading module"
	} else if (id & BPFLOCK_KM_AUTOLOAD) != 0 {
		return "autoloading module"
	} else if (id & BPFLOCK_KM_UNSAFEMOD) != 0 {
		return "unsafe module parameters"
	} else if (id & BPFLOCK_KM_UNSIGNED) != 0 {
		return "unsigned module loading"
	}

	return ""
}

func GetOperationStr(event *bpfevents.ProcessEvent) (string, error) {
	valid := true
	if event.ProgramId != bpfevents.KmodLockId {
		valid = false
	}

	switch event.EventId {
	case bpfevents.LsmLockedDownId,
		bpfevents.LSMKernelModuleRequestId,
		bpfevents.LSMKernelReadFileId,
		bpfevents.LSMKernelLoadDataId:
	default:
		valid = true
	}

	if !valid {
		return "", fmt.Errorf("not a kmodlock operation")
	}

	op := getKmodLockOp(event.OperationId)
	if op == "" {
		op = "(none)"
	}

	return op, nil
}
