// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2021 Authors of Cilium

package linux

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/option"
	"github.com/linux-lock/bpflock/pkg/version"
	"github.com/linux-lock/bpflock/pkg/versioncheck"
)

const (
	minKernelVer  = "5.13.0"
	lsmConfigFile = "/sys/kernel/security/lsm"
)

var (
	isMinKernelVer = versioncheck.MustCompile(">=" + minKernelVer)
	log            = logging.DefaultLogger.WithField(logfields.LogSubsys, "linux-bpf")
)

// CheckBpfLsmConfig() check that the kernel was compiled with:
// CONFIG_LSM="...,bpf" and CONFIG_BPF_LSM=y
func checkBpfLsmConfig() {
	b, err := ioutil.ReadFile(lsmConfigFile)
	if err != nil {
		log.WithError(err).Fatalf("reading lsm kernel config '%s'", lsmConfigFile)
	}

	if strings.Contains(string(b), "bpf") == false {
		err = fmt.Errorf("LSM BPF is not supported in this kernel")
		log.WithError(err).Fatalf("must have a kernel with 'CONFIG_BPF_LSM=y' 'CONFIG_LSM=\"...,bpf\"'")
	}
}

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

	checkBpfLsmConfig()

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		log.WithError(err).Fatalf("BPF programs directory was not found.")
	}

	if err := os.Chdir(option.Config.VarLibDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.VarLibDir).Fatal("Could not change to runtime directory")
	}
}
