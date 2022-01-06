// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017 Authors of Cilium

package version

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// BpflockVersion provides a minimal structure to the version string
type BpflockVersion struct {
	// Version is the semantic version of Bpflock
	Version string
	// Revision is the short SHA from the last commit
	Revision string
	// GoRuntimeVersion is the Go version used to run Bpflock
	GoRuntimeVersion string
	// Arch is the architecture where Bpflock was compiled
	Arch string
	// AuthorDate is the git author time reference stored as string ISO 8601 formatted
	AuthorDate string
}

// bpflockVersion is set to Bpflock's version
var bpflockVersion string

// Version is the complete Bpflock version string including Go version.
var Version string

func init() {
	// Mimic the output of `go version` and append it to ciliumVersion.
	// Report GOOS/GOARCH of the actual binary, not the system it was built on, in case it was
	// cross-compiled. See #13122
	Version = fmt.Sprintf("%s go version %s %s/%s", bpflockVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// FromString converts a version string into struct
func FromString(versionString string) BpflockVersion {
	// string to parse: "0.13.90 a722bdb 2018-01-09T22:32:37+01:00 go version go1.9 linux/amd64"
	fields := strings.Split(versionString, " ")
	if len(fields) != 7 {
		return BpflockVersion{}
	}

	cver := BpflockVersion{
		Version:          fields[0],
		Revision:         fields[1],
		AuthorDate:       fields[2],
		GoRuntimeVersion: fields[5],
		Arch:             fields[6],
	}
	return cver
}

// GetBpflockVersion returns a initialized BpflockVersion structure
func GetBpflockVersion() BpflockVersion {
	return FromString(Version)
}

// Base64 returns the version in a base64 format.
func Base64() (string, error) {
	jsonBytes, err := json.Marshal(Version)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}
