// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017-2020 Authors of Cilium

package helpers

import (
	"fmt"
	"strings"
)

// ContainerExec executes cmd in the container with the provided name along with
// any other additional arguments needed.
func (s *LocalExecutor) ContainerExec(name string, cmd string, optionalArgs ...string) *CmdRes {
	optionalArgsCoalesced := ""
	if len(optionalArgs) > 0 {
		optionalArgsCoalesced = strings.Join(optionalArgs, " ")
	}
	dockerCmd := fmt.Sprintf("docker exec -i %s %s %s", optionalArgsCoalesced, name, cmd)
	return s.Exec(dockerCmd)
}

// ContainerRun is a wrapper to a one execution docker run container. It runs
// an instance of the specific Docker image with the provided name and
// options.
func (s *LocalExecutor) ContainerRun(sudo bool, name, options, volumes, image string, cmdParams ...string) *CmdRes {
	cmdOnStart := ""
	if len(cmdParams) > 0 {
		cmdOnStart = strings.Join(cmdParams, " ")
	}
	cmd := fmt.Sprintf(
		"docker run --detach --name %s %s %s %s %s", name, options, volumes, image, cmdOnStart)
	log.Debugf("spinning up container with command '%v'", cmd)
	if sudo == true {
		return s.ExecWithSudo(cmd)
	} else {
		return s.Exec(cmd)
	}
}

// ContainerRestart
func (s *LocalExecutor) ContainerRestart(sudo bool, name string) *CmdRes {
	cmd := fmt.Sprintf("docker restart %s", name)
	if sudo == true {
		return s.ExecWithSudo(cmd)
	} else {
		return s.Exec(cmd)
	}
}

// ContainerRm is a wrapper around `docker rm -f`. It forcibly removes the
// Docker container of the provided name.
func (s *LocalExecutor) ContainerRm(sudo bool, name string) *CmdRes {
	cmd := fmt.Sprintf("docker rm -f %s", name)
	if sudo == true {
		return s.ExecWithSudo(cmd)
	} else {
		return s.Exec(cmd)
	}
}

// ContainerInspect runs `docker inspect` for the container with the provided
// name.
func (s *LocalExecutor) ContainerInspect(sudo bool, name string) *CmdRes {
	cmd := fmt.Sprintf("docker inspect %s", name)
	if sudo == true {
		return s.ExecWithSudo(cmd)
	} else {
		return s.Exec(cmd)
	}
}

/*
func (s *LocalExecutor) containerInspectNet(name string, network string) (map[string]string, error) {
	res := s.ContainerInspect(name)
	properties := map[string]string{
		"EndpointID":        "EndpointID",
		"GlobalIPv6Address": IPv6,
		"IPAddress":         IPv4,
		"NetworkID":         "NetworkID",
		"IPv6Gateway":       "IPv6Gateway",
	}

	if !res.WasSuccessful() {
		return nil, fmt.Errorf("could not inspect container %s", name)
	}
	filter := fmt.Sprintf(`{ [0].NetworkSettings.Networks.%s }`, network)
	result := map[string]string{
		Name: name,
	}
	data, err := res.FindResults(filter)
	if err != nil {
		return nil, err
	}
	for _, val := range data {
		iface := val.Interface()
		for k, v := range iface.(map[string]interface{}) {
			if key, ok := properties[k]; ok {
				result[key] = fmt.Sprintf("%s", v)
			}
		}
	}
	return result, nil
}
*/

// GatherDockerLogs dumps docker containers logs output to the directory
// specified by test
func (s *LocalExecutor) GatherDockerLogs(testName string) {
	res := s.Exec("docker ps -a --format {{.Names}}")
	if !res.WasSuccessful() {
		log.WithField("error", res.CombineOutput()).Errorf("cannot get docker logs")
		return
	}
	commands := map[string]string{}
	for _, k := range res.ByLines() {
		if k != "" {
			key := fmt.Sprintf("docker logs %s", k)
			commands[key] = fmt.Sprintf("container_%s.log", k)
		}
	}

	testPath, err := CreateReportDirectory(testName)
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, commands, s)
}
