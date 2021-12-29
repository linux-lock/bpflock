// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2018 Authors of Cilium

// Package logfields defines common logging fields which are used across packages
package logfields

const (
	// Annotations are any annotations for Pods
	Annotations = "annotations"

	// LogSubsys is the field denoting the subsystem when logging
	LogSubsys = "subsys"

	// LogBpfSubsys is the field denoting the bpf program when logging
	LogBpfSubsys = "bpfprog"

	// Signal is the field to print os signals on exit etc.
	Signal = "signal"

	// Node is a host machine in the cluster, running bpflock
	Node = "node"

	// NodeName is a human readable name for the node
	NodeName = "nodeName"

	// Path is a filesystem path. It can be a file or directory.
	Path = "file-path"

	// Line is a line number within a file
	Line = "line"

	// StartTime is the start time of an event
	StartTime = "startTime"

	// EndTime is the end time of an event
	EndTime = "endTime"

	// Duration is the duration of a measured operation
	Duration = "duration"
)
