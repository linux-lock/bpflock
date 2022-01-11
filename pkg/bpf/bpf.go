// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2018 Authors of Cilium

package bpf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/linux-lock/bpflock/pkg/command/exec"
	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/option"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bpf")

	bpfProgramsPath = filepath.Join(defaults.ProgramLibPath, "bpf")
	bpftool         = filepath.Join(defaults.ProgramLibPath, "bpftool")
)

// #rm -fr /sys/fs/bpf/bpflock/$pinnedProg
func bpftoolUnload(pinnedProg string) {
	bpffs := filepath.Join(MapPrefixPath(), pinnedProg)

	log.Infof("removing bpf-program=%s", pinnedProg)
	os.RemoveAll(bpffs)
}

// #bpftool prog show name progName
func bpftoolGetProgID(progName string) (string, error) {
	args := []string{"prog", "show", "name", progName}
	log.WithFields(logrus.Fields{
		"bpftool": bpftool,
		"args":    args,
	}).Debug("GetProgID:")
	output, err := exec.WithTimeout(defaults.ShortExecTimeout, bpftool, args...).CombinedOutput(log, false)
	if err != nil {
		return "", fmt.Errorf("Failed to show %s: %s: %s", progName, err, output)
	}

	// Scrap the prog_id out of the bpftool output after libbpf is dual licensed
	// we will use programatic API.
	s := strings.Fields(string(output))
	if s[0] == "" {
		return "", fmt.Errorf("Failed to find prog %s: %s", progName, err)
	}
	progID := strings.Split(s[0], ":")
	return progID[0], nil
}

// BpfLsmEnable will execute all programs according to configuration
// and corresponding bpf programs will be pinned automatically
func BpfLsmEnable() error {
	spec := option.Config.BpfMeta.Spec

	for _, p := range spec.Programs {
		launcher := filepath.Join(option.Config.BpfDir, p.Command)
		_, err := exec.WithTimeout(defaults.ShortExecTimeout, launcher, p.Args...).CombinedOutput(log, true)
		if err != nil {
			return fmt.Errorf("run bpf program '%s' with '%s' failed: %v", p.Name, launcher, err)
		}

		log.WithFields(logrus.Fields{
			"launcher": launcher,
			"args":     p.Args,
		}).Infof("%s: %s", p.Name, p.Description)
	}

	return nil
}

// BpfLsmDisable will detach any bpf programs and unloads them.
// All the programs and maps associated with it will be deleted
// from the bpf filesystem.
func BpfLsmDisable() error {
	p := MapPrefixPath()
	files, err := ioutil.ReadDir(p)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s': %s", p, err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name(), "..") {
			continue
		}
		if f.IsDir() {
			bpftoolUnload(f.Name())
		}
	}

	return nil
}
