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
)

// IsBpflockAgent checks whether the current process is bpflock (daemon).
func IsBpflockAgent() bool {
	binaryName := os.Args[0]
	return strings.HasSuffix(binaryName, BpflockAgentName)
}
