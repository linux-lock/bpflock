// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Djalal Harouni

//go:build linux
// +build linux

package bpfevents

import (
	"github.com/go-openapi/swag"
)

const (
	TaskCommLen = 16
	NameMax     = 255
	PathMax     = 4096

	TaskFileName = 64
	DataLen      = 64
)

const (
	INIT_USERNS_ID_INO   = 0xEFFFFFFD
	INIT_PIDNS_ID_INO    = 0xEFFFFFFC /* PROC_PID_INIT_INO */
	INIT_CGROUPNS_ID_INO = 0xEFFFFFFB /* PROC_CGROUP_INIT_INO */

	/* Chared maps */
	SharedCgroupMap = "bpflock_cgroupmap"
	SharedEvents    = "bpflock_events"
	SharedPidnsMap  = "bpflock_pidnsmap"
	SharedNetnsMap  = "bpflock_netnsmap"
	SharedMntnsMap  = "bpflock_mntnsmap"
)

var (
	SharedMaps = []string{
		SharedCgroupMap,
		SharedEvents,
		SharedPidnsMap,
		SharedNetnsMap,
		SharedMntnsMap,
	}
)

type CgroupMapEntry struct {
	Profile int `json:"profile"`
}

type PidnsMapEntry struct {
	Profile int `json:"profile"`
}

type MntnsMapEntry struct {
	Profile int `json:"profile"`
}

// ProcessEvent generated by bpf programs
type ProcessEvent struct {
	ProgType   int32  `json:"prog_type"`
	AttachType int32  `json:"attach_type"`
	PeventId   uint64 `json:"pevent_id"`

	Tgid      uint32 `json:"tgid"`
	Pid       uint32 `json:"pid"`
	Ppid      uint32 `json:"ppid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	SessionId uint32 `json:"sessionid"`

	CgroupId       uint64 `json:"cgroupid"`
	ParentCgroupId uint64 `json:"parent_cgroup_id"`

	MntnsId uint32 `json:"mntns_id"`
	PidnsId uint32 `json:"pidns_id"`
	NetnsId uint64 `json:"netns_id"`

	/* Return value of the bpf program for LSM or of the kernel function */
	ReturnValue int32 `json:"retval"`

	/* Map filters that matched the access */
	MatchedFilter int32 `json:"matched_filter"`

	/* Reason why access was allowed : enum reason_value */
	Reason int32 `json:"reason"`

	Reserved1 int32 `json:"reserved1"`

	/* Comm of the task */
	Comm [TaskCommLen]byte `json:"comm"`

	/* Comm of the parent task */
	Pcomm [TaskCommLen]byte `json:"pcomm"`

	/* Filename used in multiple events */
	FileName [TaskFileName]byte `json:"filename"`

	/* Auxiliary data */
	DataLen [DataLen]byte `json:"data"`
}

// MarshalBinary interface implementation
func (e *ProcessEvent) MarshalBinary() ([]byte, error) {
	if e == nil {
		return nil, nil
	}
	return swag.WriteJSON(e)
}

// UnmarshalBinary interface implementation
func (e *ProcessEvent) UnmarshalBinary(b []byte) error {
	var res ProcessEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*e = res
	return nil
}