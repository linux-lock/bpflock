// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2021 Authors of Cilium

package linux

import (
	"os"

	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/option"
	"github.com/linux-lock/bpflock/pkg/version"
	"github.com/linux-lock/bpflock/pkg/versioncheck"
)

const (
	minKernelVer = "5.15.0"
)

var (
	isMinKernelVer = versioncheck.MustCompile(">=" + minKernelVer)
	log            = logging.DefaultLogger.WithField(logfields.LogSubsys, "linux-bpf")
)

// CheckMinRequirements checks that minimum kernel requirements are met for
// using some BPF LSM features
func CheckMinRequirements() {
	kernelVersion, err := version.GetKernelVersion()
	if err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	if !isMinKernelVer(kernelVersion) {
		log.Fatalf("kernel version: NOT OK: minimal supported kernel "+
			"version is %s; kernel version that is running is: %s", minKernelVer, kernelVersion)
	}

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	if err := os.Chdir(option.Config.LibDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.LibDir).Fatal("Could not change to runtime directory")
	}
}