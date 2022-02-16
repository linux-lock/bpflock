// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Djalal Harouni

//go:build linux
// +build linux

package bpfprogs

import (
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

var (
	programs map[string]*BpfHandle
)

type InitProg func() (BpfProg, error)

type BpfProg interface {
	SetPinPath(pinPath string)
	SetArgs(args []string)

	Load() error

	Attach() error
	Destroy()

	Name() string
	Description() string
	GetArgs() []string

	GetOutputBuf() *ringbuf.Reader
	GetOutputBufPath() string
}

type BpfHandle struct {
	Prog BpfProg
	Init InitProg
}

func init() {
	programs = make(map[string]*BpfHandle)
}

func Register(name string, initProg InitProg) error {
	if _, ok := programs[name]; ok {
		return fmt.Errorf("bpf program %q already registered", name)
	}
	h := BpfHandle{
		Init: initProg,
	}
	programs[name] = &h

	return nil
}

// ListInitPrograms list initialized embedded Programs.
func ListInitPrograms() []string {
	p := []string{}
	for k, h := range programs {
		if h.Prog != nil {
			p = append(p, k)
		}
	}
	return p
}

// NewProgram initialize the new bpfProg
func NewProgram(name string) (BpfProg, error) {
	h, ok := programs[name]
	if !ok {
		return nil, fmt.Errorf("bpf program %q was not registered", name)
	}

	if h.Prog == nil {
		prog, err := h.Init()
		if err != nil {
			return nil, fmt.Errorf("bpf program %q failed to initialize: %v", name, err)
		}
		h.Prog = prog
	}

	return h.Prog, nil
}

// GetProgram Returns the BpfProg if initialized otherwise error
func GetProgram(name string) (BpfProg, error) {
	h, ok := programs[name]
	if !ok {
		return nil, fmt.Errorf("bpf program %q was not registered", name)
	}

	if h.Prog == nil {
		return nil, fmt.Errorf("bpf program %q was not initialized", name)
	}

	return h.Prog, nil
}

// DestroyPrograms  detach and destroy all initialized embedded bpf programs
func DestroyPrograms() error {
	for _, h := range programs {
		if h.Prog != nil {
			h.Prog.Destroy()
		}
	}
	return nil
}
