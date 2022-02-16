// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2018-2020 Authors of Cilium

package components

import (
	"os"
	"strings"
)

const (
	// BpflockAgentName is the name of bpflock agent (daemon) process name.
	BpflockAgentName = "bpflock"

	BpfRestrict  = "bpfrestrict"
	KimgLock     = "kimglock"
	KmodLock     = "kmodlock"
	FilelessLock = "filelesslock"
	ExecSnoop    = "execsnoop"
)

var (
	BpfProgDescriptions = map[string]string{
		ExecSnoop:    "Trace process exec()",
		FilelessLock: "Restrict fileless binary execution",
		KimgLock:     "Restrict both direct and indirect modification to a running kernel image",
		KmodLock:     "Restrict kernel module operations on modular kernels",
		BpfRestrict:  "Restrict access to the bpf() system call",
	}
)

func IsBpfProgInternal(name string) bool {
	switch name {
	case ExecSnoop:
		return true
	}
	return false
}

// IsBpflockAgent checks whether the current process is bpflock (daemon).
func IsBpflockAgent() bool {
	binaryName := os.Args[0]
	return strings.HasSuffix(binaryName, BpflockAgentName)
}
