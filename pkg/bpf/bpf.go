// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2018 Authors of Cilium

//go:build linux
// +build linux

package bpf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/linux-lock/bpflock/api/v1/models"
	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"
	"github.com/linux-lock/bpflock/bpf/gobpf/bpfprogs"

	// Register embedded bpf programs
	_ "github.com/linux-lock/bpflock/bpf/gobpf/execsnoop"

	"github.com/linux-lock/bpflock/pkg/command/exec"
	"github.com/linux-lock/bpflock/pkg/components"
	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/option"

	"github.com/sirupsen/logrus"
)

type RingBufferInfo struct {
	Ring *ringbuf.Reader
	Path string
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bpf")

	bpftool = filepath.Join(defaults.ProgramLibPath, "bpftool")

	// Readers will be closed by their corresponding programs
	EventReaders = make(map[string]*RingBufferInfo, 0)
)

func UnpinMaps(rootpath string, maps ...string) error {
	for _, m := range maps {
		pinnedMap := filepath.Join(rootpath, m)

		log.Infof("Cleaning remove bpf-map=%s", pinnedMap)
		os.RemoveAll(pinnedMap)
	}

	return nil
}

// FixBpfFilesPermissions changes pinned map permissions to 0600
// os.FileMode(0600)
func FixBpfFilesPermissions(dir string, mode os.FileMode, files ...string) error {
	fileList := []string{}
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		for _, pattern := range files {
			if regexp.MustCompile(pattern).MatchString(f.Name()) {
				fileList = append(fileList, path)
				break
			}
		}
		return nil
	})

	for _, fileToChange := range fileList {
		if err := os.Chmod(fileToChange, mode); err != nil {
			return err
		}
		log.Debugf("Changed permission of '%s'", fileToChange)
	}

	return err
}

// #rm -fr /sys/fs/bpf/bpflock/$pinnedProg
func bpftoolUnload(pinnedProg string) {
	bpffs := filepath.Join(MapPrefixPath(), pinnedProg)

	log.WithFields(logrus.Fields{
		logfields.LogBpfSubsys: pinnedProg,
	}).Infof("Cleaning remove bpf-program=%s", pinnedProg)
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

func runBpfProgram(p *models.BpfProgram) error {
	var loader string

	// Run c based bpf programs loaded with libbpf
	if p.Command != components.BpflockAgentName {
		loader = filepath.Join(option.Config.BpfDir, p.Command)
		_, err := os.Stat(loader)
		if err != nil {
			log.WithError(err).Warnf("run bpf program '%s' failed: unable to find loader '%q'", p.Name, loader)
			return err
		}

		_, err = exec.WithTimeout(defaults.ShortExecTimeout, loader, p.Args...).CombinedOutput(log, true)
		if err != nil {
			// Let's not fail execution but report it
			log.WithError(err).Warnf("run bpf program '%s' with '%q' failed", p.Name, loader)
			return err
		}
	} else {
		// Run embededd golang bpf programs
		loader = filepath.Join(defaults.ProgramLibPath, p.Command)
		prog, err := bpfprogs.NewProgram(p.Name)
		if err != nil {
			log.WithError(err).Warnf("initialize bpf program '%s' failed", p.Name)
			return err
		}

		prog.SetPinPath(GetMapRoot())
		prog.SetArgs(p.Args)

		err = prog.Load()
		if err != nil {
			log.WithError(err).Warnf("Load bpf program '%s' failed", p.Name)
			return err
		}

		err = prog.Attach()
		if err != nil {
			log.WithError(err).Fatalf("Attach embedded bpf program '%s' failed", prog.Name())
			return err
		}

		info := &RingBufferInfo{
			Ring: prog.GetOutputBuf(),
			Path: prog.GetOutputBufPath(),
		}
		EventReaders[prog.Name()] = info
	}

	log.WithFields(logrus.Fields{
		logfields.LogBpfSubsys: p.Name,
		"loader":               loader,
		"args":                 p.Args,
	}).Infof("Started bpf program %s: %s", p.Name, p.Description)

	return nil
}

// BpfLsmEnable will execute all programs according to configuration
// and corresponding bpf programs will be pinned automatically
func BpfLsmEnable() error {
	spec := option.Config.BpfMeta.Bpfspec

	i := 0
	for _, p := range spec.Programs {
		err := runBpfProgram(p)
		if err == nil {
			i++
		}
	}

	if i == 0 {
		return fmt.Errorf("unable to start bpf programs: all failed")
	}

	return nil
}

func DestroyEmbeddedProgs() {
	bpfprogs.DestroyPrograms()
}

// BpfLsmDisable will detach any bpf programs and unload them.
// All the programs and maps associated with it will be deleted
// from the bpf filesystem including shared maps
func BpfLsmDisable() error {
	p := MapPrefixPath()
	files, err := ioutil.ReadDir(p)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s': %s", p, err)
	}

	// Destroy embedded programs first
	DestroyEmbeddedProgs()

	for _, f := range files {
		if strings.HasPrefix(f.Name(), "..") {
			continue
		}
		if f.IsDir() {
			bpftoolUnload(f.Name())
		}
	}

	// Let's detach previously shared maps and in future we should
	// restore previous context
	p = GetMapRoot()
	return UnpinMaps(p, bpfevents.SharedMaps...)
}
