// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package option

import ()

const (
	Debug = "Debug"
)

var (
	specDebug = Option{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}
)
