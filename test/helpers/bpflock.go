// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017-2020 Authors of Cilium

package helpers

import (
	"fmt"
	"time"

	"github.com/linux-lock/bpflock/pkg/logging"
)

var log = logging.DefaultLogger

const (
	BpflockContainer        = "bpflock"
	BpflockBuilderContainer = "bpflock-builder"
	BpflockIntegration      = "bpflock-integration"
	BpflockOpts             = "-it --rm --pid=host --privileged"
	BpflockVolumes          = "-v /sys/kernel/security:/sys/kernel/security -v /sys/fs/bpf:/sys/fs/bpf"
	BpflockImage            = "linuxlock/bpflock:latest"
	BpflockIntegrationImage = "linuxlock/bpflock-integration:latest"

	// Will automatically look for the configuration in /etc/bpflock/
	// then inside /usr/lib/bpflock/
	BpflockProfileDeny     = "--config=docker-deny.yaml"
	BpflockProfileRestrict = "--config=docker-restrict.yaml"
	BpflockProfileAllow    = "--config=docker-allow.yaml"
)

// Runs a bpflock command and returns the resultant cmdRes.
func (s *LocalExecutor) ExecBpflock(cmd string) *CmdRes {
	command := fmt.Sprintf("bpflock %s", cmd)
	return s.ExecWithSudo(command)
}

// WaitUntilReady waits until the output of `bpflock status` returns with code
// zero. Returns an error if the output of `bpflock status` returns a nonzero
// return code after the specified timeout duration has elapsed.
func (s *LocalExecutor) WaitUntilReady(timeout time.Duration) error {
	body := func() bool {
		res := s.ExecBpflock("status")
		s.logger.Infof("bpflock status is %t", res.WasSuccessful())
		return res.WasSuccessful()
	}
	err := WithTimeout(body, "bpflock is not ready", &TimeoutConfig{Timeout: timeout})
	return err
}

// WaitUntilReadyContainer waits until the output of docker container inspect returns the code
// with zero and container status is running. Returns a nonzero after the specified timeout
// duration has elapsed.
func (s *LocalExecutor) WaitUntilReadyContainer(containerName string, timeout time.Duration) error {
	body := func() bool {
		command := fmt.Sprintf("docker container inspect --format='{{.State.Status}}' %s", containerName)
		res := s.Exec(command)
		s.logger.Infof("docker container inspect on %s is %t", containerName, res.WasSuccessful())
		if res.WasSuccessful() && res.ExpectMatchesRegexp("running") {
			return true
		} else {
			return false
		}
	}
	msg := fmt.Sprintf("docker container %s is not ready", containerName)
	err := WithTimeout(body, msg, &TimeoutConfig{Timeout: timeout})
	return err
}

// RestartBpflockContainer reloads bpflock container on this host, then waits for it to become
// ready again.
func (s *LocalExecutor) RunBpflockContainer(sudo bool, name, options, volumes, image string, cmdParams string) error {
	res := s.ContainerRun(sudo, name, options, volumes, image, cmdParams)
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return s.WaitUntilReadyContainer(name, BpflockStartTimeout)
}

func (s *LocalExecutor) RmBpflockContainer(name string) error {
	res := s.ContainerRm(false, name)
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
}
