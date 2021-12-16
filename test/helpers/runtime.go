// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017 Authors of Cilium

package helpers

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

// InitRuntimeHelper returns SSHMeta helper for running the runtime tests
// on the provided VM target and using logger 'log'. It marks the test as Fail
// if it cannot get the ssh meta information or cannot execute a `ls` on the
// virtual machine.
/*
func InitRuntimeHelper(target string, log *logrus.Entry) *SSHMeta {
	node := GetVagrantSSHMeta(target)
	if node == nil {
		ginkgo.Fail(fmt.Sprintf("Cannot connect to target '%s'", target), 1)
		return nil
	}

	// This `ls` command is a sanity check, sometimes the meta ssh info is not
	// nil but new commands cannot be executed using SSH, tests failed and it
	// was hard to debug.
	res := node.Exec("ls /tmp/")
	if !res.WasSuccessful() {
		ginkgo.Fail(fmt.Sprintf(
			"Cannot execute ls command on target '%s'", target), 1)
		return nil
	}

	node.logger = log
	return node
}
*/

func InitLocalRuntimeHelper(logger *logrus.Entry) (*LocalExecutor, error) {
	var environ []string
	var exec *LocalExecutor

	exec = CreateLocalExecutor(environ)
	err := exec.setBasePath()
	if err != nil {
		return nil, fmt.Errorf("setBasePath() failed with: '%s'", err.Error())
	}

	// Set logger here
	exec.logger = logger

	res := exec.Exec("id")
	if res.WasSuccessful() == false {
		return nil, fmt.Errorf("Exec(id) failed with: '%s'", res.err)
	}

	return exec, nil
}
