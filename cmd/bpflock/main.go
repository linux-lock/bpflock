// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2018 Authors of Cilium

// Ensure build fails on versions of Go that are not supported by bpflock.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.17
// +build go1.17

package main

import (
	cmd "github.com/linux-lock/bpflock/pkg/daemon"
)

func main() {
	cmd.Execute()
}
