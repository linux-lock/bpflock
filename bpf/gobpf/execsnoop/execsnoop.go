// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2021 Djalal Harouni

//go:build linux
// +build linux

package execsnoop

import (
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"

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
	name string

	description string

	// bpfObjects contains all objects after they have been loaded into the kernel.
	objs bpfObjects

	sysEnterExecve link.Link
	sysExitExecve  link.Link

	ring *ringbuf.Reader

	// pinPath will contain the root path where maps are pinned
	pinPath string

	args []string
}

func NewBpf() (*ExecSnoopBpf, error) {
	return &ExecSnoopBpf{
		name:        components.ExecSnoop,
		description: "trace process exec()",
		args:        make([]string, 0),
	}, nil
}

func (e *ExecSnoopBpf) GetName() string {
	return e.name
}

func (e *ExecSnoopBpf) GetDescription() string {
	return e.description
}

func (e *ExecSnoopBpf) GetArgs() []string {
	return e.args
}

func (e *ExecSnoopBpf) Load(pinPath string) error {
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Errorf("can not remove memory lock")
		return err
	}

	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		log.WithError(err).Errorf("loading '%s' objects failed", e.name)
		return err
	}

	e.objs = objs
	e.pinPath = pinPath

	return nil
}

func (e *ExecSnoopBpf) SetArgs(traceTarget string) error {
	key := uint32(ExecSnoopTraceTarget)
	path := filepath.Join(e.pinPath, ExecSnoopArgsMap)
	loadOpts := &ebpf.LoadPinOptions{}

	m, err := ebpf.LoadPinnedMap(path, loadOpts)
	if err != nil {
		log.Warnf("Execsnoop ignored, loading pinned map '%s' failed: %v", path, err)
		return nil
	}

	switch traceTarget {
	case defaults.ExecSnoopByFilter:
		value := uint32(ExecSnoopTraceByFilter)
		err = m.Put(key, value)
	case defaults.ExecSnoopAll:
		value := uint32(ExecSnoopTraceAll)
		err = m.Put(key, value)
	}

	if err != nil {
		log.Warnf("Execsnoop ignored, updating map '%s' failed: %v", path, err)
		return nil
	}

	e.args = append(e.args, traceTarget)

	return nil
}

func (e *ExecSnoopBpf) Attach(target string) error {
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve",
		e.objs.TracepointSyscallsSysEnterExecve)
	if err != nil {
		e.Detach()
		log.WithError(err).Errorf("opening tracepoint 'sys_enter_execve' failed")
		return err
	}

	e.sysEnterExecve = tp

	tp, err = link.Tracepoint("syscalls", "sys_exit_execve",
		e.objs.TracepointSyscallsSysExitExecve)
	if err != nil {
		e.Detach()
		log.WithError(err).Errorf("opening tracepoint 'sys_exit_execve' failed")
	}

	e.sysExitExecve = tp

	err = e.SetArgs(target)
	if err != nil {
		e.Detach()
		log.WithError(err).Errorf("setArgs() failed")
		return err
	}

	rd, err := ringbuf.NewReader(e.objs.BpflockEvents)
	if err != nil {
		e.Detach()
		log.WithError(err).Errorf("opening ringbuffer reader")
		return err
	}

	e.ring = rd

	log.Infof("ring buffer at: %p    %+v\n", rd, rd)

	return nil
}

func (e *ExecSnoopBpf) GetRingBufferPath() string {
	return filepath.Join(e.pinPath, bpfevents.SharedEvents)
}

func (e *ExecSnoopBpf) GetRingBuffer() *ringbuf.Reader {
	return e.ring
}

func (e *ExecSnoopBpf) CloseBuffer() {
	if e.ring != nil {
		e.ring.Close()
		e.ring = nil
	}
}

// UnpinLocalMaps removes non shared maps only
func (e *ExecSnoopBpf) UnpinLocalMaps() {
	pinnedMap := filepath.Join(e.pinPath, "bpflock_execsnoop_storage")
	log.Infof("Cleaning remove bpf-map=%s", pinnedMap)
	os.RemoveAll(pinnedMap)

	pinnedMap = filepath.Join(e.pinPath, "bpflock_execsnoop_args")
	log.Infof("Cleaning remove bpf-map=%s", pinnedMap)
	os.RemoveAll(pinnedMap)
}

func (e *ExecSnoopBpf) closeLinks() {
	if e.sysExitExecve != nil {
		e.sysExitExecve.Close()
		e.sysExitExecve = nil
	}

	if e.sysEnterExecve != nil {
		e.sysEnterExecve.Close()
		e.sysEnterExecve = nil
	}
}

// CloseExecSnoop remove and detach execsnoop resources
func (e *ExecSnoopBpf) Detach() {
	e.CloseBuffer()
	e.closeLinks()
	e.objs.Close()
	log.Infof("Cleaning remove bpf-program=%s", e.GetName())
}

// Clean  cleans up everything related to execsnoop and closes ring buffer
func (e *ExecSnoopBpf) Destroy() {
	e.Detach()
	e.UnpinLocalMaps()
}
