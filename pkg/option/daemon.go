// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium

package option

var (
	// DaemonOptionLibrary is the daemon's option library that should be
	// used for read-only.
	DaemonOptionLibrary = OptionLibrary{}

	DaemonMutableOptionLibrary = OptionLibrary{
		Debug: &specDebug,
	}
)

func init() {
	for k, v := range DaemonMutableOptionLibrary {
		DaemonOptionLibrary[k] = v
	}
}

// ParseDaemonOption parses a string as daemon option
func ParseDaemonOption(opt string) (string, OptionSetting, error) {
	return ParseOption(opt, &DaemonOptionLibrary)
}
