// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2021 Djalal Harouni

//go:build linux
// +build linux

package execsnoop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"
	"github.com/linux-lock/bpflock/bpf/gobpf/bpfprogs"

	"github.com/linux-lock/bpflock/pkg/components"
	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	ExecSnoopEventMStorage = "bpflock_execsnoop_storage"
	ExecSnoopArgsMap       = "bpflock_execsnoop_args"

	ExecSnoopProfile     = 1
	ExecSnoopTraceTarget = 2
	ExecSnoopDebug       = 5
)

const (
	/* The following are how we should trace: key is ExecSnoopTraceTarget */
	ExecSnoopTraceByFilter = iota + 1
	ExecSnoopTraceAll
)

var (
	bpfProgram = components.ExecSnoop
	log        = logging.DefaultLogger.WithFields(logrus.Fields{
		logfields.LogSubsys:    "bpf",
		logfields.LogBpfSubsys: bpfProgram,
	})
)

type ExecSnoopBpf struct {
	name        string
	description string

	// bpfObjects contains all objects after they have been loaded into the kernel.
	objs bpfObjects

	sysEnterExecveAt link.Link
	sysExitExecveAt  link.Link
	sysEnterExecve   link.Link
	sysExitExecve    link.Link

	ring *ringbuf.Reader

	// pinPath will contain the root path where maps are pinned
	pinPath string

	args []string

	attachOnce  sync.Once
	destroyOnce sync.Once
	attached    bool
}

func init() {
	bpfprogs.Register(bpfProgram, Init)
}

func Init() (bpfprogs.BpfProg, error) {
	return &ExecSnoopBpf{
		name:        components.ExecSnoop,
		description: components.BpfProgDescriptions[components.ExecSnoop],
		args:        make([]string, 0),
	}, nil
}

func (e *ExecSnoopBpf) SetPinPath(pinPath string) {
	e.pinPath = pinPath
}

func (e *ExecSnoopBpf) Name() string {
	return e.name
}

func (e *ExecSnoopBpf) Description() string {
	return e.description
}

func (e *ExecSnoopBpf) SetArgs(args []string) {
	e.args = args
}

func (e *ExecSnoopBpf) GetArgs() []string {
	return e.args
}

func (e *ExecSnoopBpf) Load() error {
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Errorf("can not remove memory lock")
		return err
	}

	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: e.pinPath,
		},
	}); err != nil {
		log.WithError(err).Errorf("loading '%s' objects failed", e.name)
		return err
	}

	e.objs = objs

	return nil
}

func (e *ExecSnoopBpf) setupMaps() error {
	target := ""

	// We support only one argument for now
	a := strings.Split(e.args[0], "=")
	if len(a) != 2 {
		return nil
	}
	target = a[1]

	key := uint32(ExecSnoopTraceTarget)
	path := filepath.Join(e.pinPath, ExecSnoopArgsMap)
	loadOpts := &ebpf.LoadPinOptions{}

	m, err := ebpf.LoadPinnedMap(path, loadOpts)
	if err != nil {
		log.Warnf("Execsnoop ignored, loading pinned map '%s' failed: %v", path, err)
		return nil
	}

	switch target {
	case defaults.ExecSnoopByFilter:
		value := uint32(ExecSnoopTraceByFilter)
		err = m.Put(key, value)
	case defaults.ExecSnoopAll:
		value := uint32(ExecSnoopTraceAll)
		err = m.Put(key, value)
	}

	if err != nil {
		log.Warnf("bpf program %s ignored, updating map '%s' failed: %v", e.Name(), path, err)
		return nil
	}

	return nil
}

func (e *ExecSnoopBpf) Attach() error {
	if e.attached {
		return nil
	}

	e.attachOnce.Do(func() {
		err := e.attach()
		if err != nil {
			log.WithError(err).Warnf("attach bpf program '%s' failed", e.Name())
		}
	})

	if e.attached == false {
		return fmt.Errorf("attach bpf program %s failed", e.Name())
	}

	return nil
}

func (e *ExecSnoopBpf) attach() error {
	e.attached = true
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve",
		e.objs.TracepointSyscallsSysEnterExecve)
	if err != nil {
		e.Destroy()
		log.WithError(err).Errorf("opening tracepoint 'sys_enter_execve' failed")
		return err
	}

	e.sysEnterExecve = tp

	tp, err = link.Tracepoint("syscalls", "sys_exit_execve",
		e.objs.TracepointSyscallsSysExitExecve)
	if err != nil {
		e.Destroy()
		log.WithError(err).Errorf("opening tracepoint 'sys_exit_execve' failed")
		return err
	}
	e.sysExitExecve = tp

	tp, err = link.Tracepoint("syscalls", "sys_enter_execveat",
		e.objs.TracepointSyscallsSysEnterExecveat)
	if err != nil {
		e.Destroy()
		log.WithError(err).Errorf("opening tracepoint 'sys_enter_execveat' failed")
		return err
	}
	e.sysEnterExecveAt = tp

	tp, err = link.Tracepoint("syscalls", "sys_exit_execveat",
		e.objs.TracepointSyscallsSysExitExecveat)
	if err != nil {
		e.Destroy()
		log.WithError(err).Errorf("opening tracepoint 'sys_exit_execveat' failed")
		return err
	}
	e.sysExitExecveAt = tp

	err = e.setupMaps()
	if err != nil {
		e.Destroy()
		log.WithError(err).Errorf("setupMaps() failed")
		return err
	}

	rd, err := ringbuf.NewReader(e.objs.BpflockEvents)
	if err != nil {
		e.Destroy()
		log.WithError(err).Errorf("opening ringbuffer reader")
		return err
	}

	e.ring = rd
	return nil
}

func (e *ExecSnoopBpf) GetOutputBufPath() string {
	return filepath.Join(e.pinPath, bpfevents.SharedEvents)
}

func (e *ExecSnoopBpf) GetOutputBuf() *ringbuf.Reader {
	return e.ring
}

func (e *ExecSnoopBpf) closeBuffer() {
	if e.ring != nil {
		e.ring.Close()
		e.ring = nil
	}
}

// unpinLocalMaps removes non shared maps only
func (e *ExecSnoopBpf) unpinLocalMaps() {
	pinnedMap := filepath.Join(e.pinPath, "bpflock_execsnoop_storage")
	log.Infof("Cleaning remove bpf-map=%s", pinnedMap)
	os.RemoveAll(pinnedMap)

	pinnedMap = filepath.Join(e.pinPath, "bpflock_execsnoop_args")
	log.Infof("Cleaning remove bpf-map=%s", pinnedMap)
	os.RemoveAll(pinnedMap)
}

func _execSnoopCloseLinks(links ...link.Link) {
	for _, l := range links {
		if l != nil {
			l.Close()
			l = nil
		}
	}
}

func (e *ExecSnoopBpf) closeLinks() {
	_execSnoopCloseLinks(
		e.sysEnterExecve,
		e.sysEnterExecveAt,
		e.sysExitExecve,
		e.sysExitExecveAt,
	)
}

// Detach remove and detach execsnoop program
func (e *ExecSnoopBpf) detach() {
	e.closeBuffer()
	e.closeLinks()
	e.objs.Close()
	log.Infof("Cleaning remove bpf-program=%s", e.Name())
}

// Destroy  cleans up everything related to execsnoop and remove ring buffer
func (e *ExecSnoopBpf) Destroy() {
	if e.attached {
		e.destroyOnce.Do(func() {
			e.detach()
			e.unpinLocalMaps()
		})
		e.attached = false
	}
}
