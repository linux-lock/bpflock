// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2019-2020 Authors of Cilium

package daemon

import (
	"github.com/linux-lock/bpflock/pkg/sysctl"
)

func applySystemSettings() {
	sysSettings := []sysctl.Setting{
		{Name: "kernel.unprivileged_bpf_disabled", Val: "1", IgnoreErr: true},
	}
	sysctl.ApplySettings(sysSettings)
}
