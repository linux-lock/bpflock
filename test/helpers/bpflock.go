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
	// MaxRetries is the number of times that a loop should iterate until a
	// specified condition is not met
	MaxRetries = 30
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

// RestartBpflock reloads bpflock on this host, then waits for it to become
// ready again.
func (s *LocalExecutor) RestartBpflock() error {
	res := s.ExecWithSudo("docker restart bpflock")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	if err := s.WaitUntilReady(BpflockStartTimeout); err != nil {
		return err
	}
	return nil
}
