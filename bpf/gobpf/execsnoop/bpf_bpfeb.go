// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package execsnoop

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	TracepointSyscallsSysEnterExecve   *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_enter_execve"`
	TracepointSyscallsSysEnterExecveat *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_enter_execveat"`
	TracepointSyscallsSysExitExecve    *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_exit_execve"`
	TracepointSyscallsSysExitExecveat  *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_exit_execveat"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	BpflockCgroupmap        *ebpf.MapSpec `ebpf:"bpflock_cgroupmap"`
	BpflockEvents           *ebpf.MapSpec `ebpf:"bpflock_events"`
	BpflockExecsnoopArgs    *ebpf.MapSpec `ebpf:"bpflock_execsnoop_args"`
	BpflockExecsnoopStorage *ebpf.MapSpec `ebpf:"bpflock_execsnoop_storage"`
	BpflockMntnsmap         *ebpf.MapSpec `ebpf:"bpflock_mntnsmap"`
	BpflockNetnsmap         *ebpf.MapSpec `ebpf:"bpflock_netnsmap"`
	BpflockPidnsmap         *ebpf.MapSpec `ebpf:"bpflock_pidnsmap"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	BpflockCgroupmap        *ebpf.Map `ebpf:"bpflock_cgroupmap"`
	BpflockEvents           *ebpf.Map `ebpf:"bpflock_events"`
	BpflockExecsnoopArgs    *ebpf.Map `ebpf:"bpflock_execsnoop_args"`
	BpflockExecsnoopStorage *ebpf.Map `ebpf:"bpflock_execsnoop_storage"`
	BpflockMntnsmap         *ebpf.Map `ebpf:"bpflock_mntnsmap"`
	BpflockNetnsmap         *ebpf.Map `ebpf:"bpflock_netnsmap"`
	BpflockPidnsmap         *ebpf.Map `ebpf:"bpflock_pidnsmap"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.BpflockCgroupmap,
		m.BpflockEvents,
		m.BpflockExecsnoopArgs,
		m.BpflockExecsnoopStorage,
		m.BpflockMntnsmap,
		m.BpflockNetnsmap,
		m.BpflockPidnsmap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	TracepointSyscallsSysEnterExecve   *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_execve"`
	TracepointSyscallsSysEnterExecveat *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_execveat"`
	TracepointSyscallsSysExitExecve    *ebpf.Program `ebpf:"tracepoint__syscalls__sys_exit_execve"`
	TracepointSyscallsSysExitExecveat  *ebpf.Program `ebpf:"tracepoint__syscalls__sys_exit_execveat"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.TracepointSyscallsSysEnterExecve,
		p.TracepointSyscallsSysEnterExecveat,
		p.TracepointSyscallsSysExitExecve,
		p.TracepointSyscallsSysExitExecveat,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
