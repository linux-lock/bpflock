// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Djalal Harouni

//go:build linux
// +build linux

package bpfevents

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

const (
	BpflockReasonNone               = iota
	BpflockReasonAllow              /* Allow */
	BpflockReasonBaselineAllowed    /* Baseline but allowed with exception */
	BpflockReasonBaseline           /* Baseline */
	BpflockReasonBaselineRestricted /* Baseline but restricted */
	BpflockReasonRestricted         /* Restricted */
	BpflockMaxReasons
)

// Event Ids keep synched with bpflock_shared_objects_ids.h
const (
	ExecSnoopId = iota + 1
	BpfRestrictId
	KmodLockId
	KimgLockId
	FilelessLockId
)

const (
	SysCallExecveId = iota + 1000
	SysCallExecveatId
)

const (
	SysCallBpfId = iota + 1100
)

const (
	LsmBpfId = iota + 10000
	LsmBpfMapId
)

const (
	LsmLockedDownId = iota + 10100
)

const (
	LSMKernelModuleRequestId = iota + 10200
	LSMKernelReadFileId
	LSMKernelLoadDataId
)

const (
	LSMBprmCredsFromFile = iota + 10300
)

var (
	SharedMaps = []string{
		SharedCgroupMap,
		SharedEvents,
		SharedPidnsMap,
		SharedNetnsMap,
		SharedMntnsMap,
	}

	ProgramIds = map[int]string{
		ExecSnoopId:    "execsnoop",
		BpfRestrictId:  "bpfrestrict",
		KmodLockId:     "kmodlock",
		KimgLockId:     "kimglock",
		FilelessLockId: "filelesslock",
	}

	// Event Ids should contain only SYSCALLS, Used LSMs
	// other probes that do not change in the kernel
	EventIds = map[int]string{
		SysCallExecveId:          "syscall_execve",
		SysCallExecveatId:        "syscall_execveat",
		SysCallBpfId:             "syscall_bpf",
		LsmBpfId:                 "lsm_bpf",
		LsmBpfMapId:              "lsm_bpf_map",
		LsmLockedDownId:          "lsm_locked_down",
		LSMKernelModuleRequestId: "lsm_kernel_module_request",
		LSMKernelReadFileId:      "lsm_kernel_read_file",
		LSMKernelLoadDataId:      "lsm_kernel_load_data",
		LSMBprmCredsFromFile:     "lsm_bprm_creds_from_file",
	}

	ReasonStr = map[int]string{
		BpflockReasonNone:               "(none)",
		BpflockReasonAllow:              "allow (privileged)",
		BpflockReasonBaselineAllowed:    "allow (baseline)",
		BpflockReasonBaseline:           "baseline",
		BpflockReasonBaselineRestricted: "denied (baseline)",
		BpflockReasonRestricted:         "denied (restricted)",
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
	ProgType   int32 `json:"prog_type"`
	AttachType int32 `json:"attach_type"`
	ProgramId  int32 `json:"program_id"`
	EventId    int32 `json:"event_id"`

	OperationId int32 `json:"operation_id"`

	Tgid      uint32 `json:"tgid"`
	Pid       uint32 `json:"pid"`
	Ppid      uint32 `json:"ppid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	SessionId uint32 `json:"sessionid"`
	Reserved1 int32  `json:"reserved1"`

	CgroupId       uint64 `json:"cgroupid"`
	ParentCgroupId uint64 `json:"parent_cgroup_id"`

	MntnsId uint32 `json:"mntns_id"`
	PidnsId uint32 `json:"pidns_id"`
	NetnsId uint64 `json:"netns_id"`

	/* Return value of the bpf program for LSM or of the kernel function */
	ReturnValue int32 `json:"retval"`

	/* Map filters that matched the access */
	MatchedFilter int32 `json:"matched_filter"`

	/* Reason why access was allowed or denied : enum reason_value */
	Reason int32 `json:"reason"`

	Reserved2 int32 `json:"reserved2"`

	/* Comm of the task */
	Comm [TaskCommLen]byte `json:"comm"`

	/* Comm of the parent task */
	Pcomm [TaskCommLen]byte `json:"pcomm"`

	/* Filename used in multiple events */
	FileName [TaskFileName]byte `json:"filename"`

	/* Auxiliary data */
	Data [DataLen]byte `json:"data"`
}
