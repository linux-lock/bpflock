// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017-2020 Authors of Cilium

package helpers

import (
	"os"
	"time"
)

var (
	// HelperTimeout is a predefined timeout value for commands.
	HelperTimeout = 2 * time.Minute

	// ShortCommandTimeout is a timeout for commands which should not take a
	// long time to execute.
	ShortCommandTimeout = 10 * time.Second

	// MidCommandTimeout is a timeout for commands which may take a bit longer
	// than ShortCommandTimeout, but less time than HelperTimeout to execute.
	MidCommandTimeout = 30 * time.Second

	// Startup timeout
	BpflockStartTimeout = 20 * time.Second
)

const (

	//BpflockTestPath is the path where bpflock test code is located.
	BpflockTestPath = "/src/github.com/linux-lock/bpflock/test"

	TestResultsPath = "test_results/"
	RunDir          = "/var/run/bpflock"
	LibDir          = "/var/lib/bpflock"

	LogPerm = os.FileMode(0666)
)
