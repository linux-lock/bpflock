// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Djalal Harouni

package bpfrestrict

import (
	"fmt"

	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"
)

const (
	BPF_MAP_CREATE = 0
	BPF_PROG_LOAD  = 5
	BPF_BTF_LOAD   = 19

	/* This one is special */
	LOCKDOWN_BPF_WRITE_USER = 16
)

func getKmodLockOp(cmd int32) string {
	switch int(cmd) {
	case BPF_MAP_CREATE:
		return "bpf_map_create"
	case BPF_PROG_LOAD:
		return "bpf_prog_load"
	case BPF_BTF_LOAD:
		return "bpf_btf_load"
	case LOCKDOWN_BPF_WRITE_USER:
		return "use of bpf to write user RAM"
	}

	return ""
}

func GetOperationStr(event *bpfevents.ProcessEvent) (string, error) {
	valid := true
	if event.ProgramId != bpfevents.BpfRestrictId {
		valid = false
	}

	switch event.EventId {
	case bpfevents.LsmBpfId,
		bpfevents.LsmBpfMapId,
		bpfevents.LsmLockedDownId:
	default:
		valid = true
	}

	if !valid {
		return "", fmt.Errorf("not a bpfrestrict operation")
	}

	op := getKmodLockOp(event.OperationId)
	if op == "" {
		op = "(none)"
	}

	return op, nil
}
