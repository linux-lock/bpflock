// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2020 Authors of Cilium

package defaults

import (
	"time"
)

const (
	// AgentHealthPort is the default value for option.AgentHealthPort
	AgentHealthPort = 9876

	// GopsPortAgent is the default value for option.GopsPort in the agent
	GopsPortAgent = 9890

	// GopsPortOperator is the default value for option.GopsPort in the operator
	GopsPortOperator = 9891

	// GopsPortApiserver is the default value for option.GopsPort in the apiserver
	GopsPortApiserver = 9892

	// RuntimePath is the default path to the runtime directory
	RuntimePath = "/var/run/bpflock"

	// RuntimePathRights are the default access rights of the RuntimePath directory
	RuntimePathRights = 0775

	// StateDirRights are the default access rights of the state directory
	StateDirRights = 0770

	//StateDir is the default path for the state directory relative to RuntimePath
	StateDir = "state"

	// TemplatesDir is the default path for the compiled template objects relative to StateDir
	TemplatesDir = "templates"

	// TemplatePath is the default path for a symlink to a template relative to StateDir/<EPID>
	TemplatePath = "template.o"

	// BpfDir is the default path for template files relative to LibDir
	BpfDir = "bpf"

	// ConfigurationPath
	ConfigurationPath = "/etc/bpflock/"

	// ProgramLibraryPath is the default path for the bpflock libraries and programs
	ProgramLibraryPath = "/usr/lib/bpflock"

	// VariablePath is the default path to the bpflock variable state directory
	VariablePath = "/var/lib/bpflock"

	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = RuntimePath + "/bpflock.sock"

	// SockPathEnv is the environment variable to overwrite SockPath
	SockPathEnv = "BPFLOCK_SOCK"

	// MonitorSockPath1_2 is the path to the UNIX domain socket used to
	// distribute BPF and agent events to listeners.
	// This is the 1.2 protocol version.
	MonitorSockPath1_2 = RuntimePath + "/monitor1_2.sock"

	// PidFilePath is the path to the pid file for the agent.
	PidFilePath = RuntimePath + "/bpflock.pid"

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultMapPrefix
	DefaultMapPrefix = "bpflock"

	// ClientConnectTimeout is the time the bpflock agent client is
	// (optionally) waiting before returning an error.
	ClientConnectTimeout = 30 * time.Second

	// StatusCollectorInterval is the interval between a probe invocations
	StatusCollectorInterval = 5 * time.Second

	// StatusCollectorWarningThreshold is the duration after which a probe
	// is declared as stale
	StatusCollectorWarningThreshold = 15 * time.Second

	// StatusCollectorFailureThreshold is the duration after which a probe
	// is considered failed
	StatusCollectorFailureThreshold = 1 * time.Minute
)
