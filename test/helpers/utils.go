// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017-2021 Authors of Cilium

package helpers

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/pkg/rand"
)

// ensure that our random numbers are seeded differently on each run
var randGen = rand.NewSafeRand(time.Now().UnixNano())

// Sleep sleeps for the specified duration in seconds
func Sleep(delay time.Duration) {
	time.Sleep(delay * time.Second)
}

// CountValues returns the count of the occurrences of key in data, as well as
// the length of data.
func CountValues(key string, data []string) (int, int) {
	var result int

	for _, x := range data {
		if x == key {
			result++
		}
	}
	return result, len(data)
}

// MakeUID returns a randomly generated string.
func MakeUID() string {
	return fmt.Sprintf("%08x", randGen.Uint32())
}

// RenderTemplate renders a text/template string into a buffer.
// Returns eturn an error if the template cannot be validated.
func RenderTemplate(tmplt string) (*bytes.Buffer, error) {
	t, err := template.New("").Parse(tmplt)
	if err != nil {
		return nil, err
	}
	content := new(bytes.Buffer)
	err = t.Execute(content, nil)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// TimeoutConfig represents the configuration for the timeout of a command.
type TimeoutConfig struct {
	Ticker  time.Duration // Check interval
	Timeout time.Duration // Limit for how long to spend in the command
}

// Validate ensuires that the parameters for the TimeoutConfig are reasonable
// for running in tests.
func (c *TimeoutConfig) Validate() error {
	if c.Timeout < 5*time.Second {
		return fmt.Errorf("Timeout too short (must be at least 5 seconds): %v", c.Timeout)
	}
	if c.Ticker == 0 {
		c.Ticker = 1 * time.Second
	} else if c.Ticker < time.Second {
		return fmt.Errorf("Timeout config Ticker interval too short (must be at least 1 second): %v", c.Ticker)
	}
	return nil
}

// WithTimeout executes body using the time interval specified in config until
// the timeout in config is reached. Returns an error if the timeout is
// exceeded for body to execute successfully.
func WithTimeout(body func() bool, msg string, config *TimeoutConfig) error {
	err := RepeatUntilTrue(body, config)
	if err != nil {
		return fmt.Errorf("%s: %s", msg, err)
	}

	return nil
}

// RepeatUntilTrueDefaultTimeout calls RepeatUntilTrue with the default timeout
// HelperTimeout
func RepeatUntilTrueDefaultTimeout(body func() bool) error {
	return RepeatUntilTrue(body, &TimeoutConfig{Timeout: HelperTimeout})
}

// RepeatUntilTrue repeatedly calls body until body returns true or the timeout
// expires
func RepeatUntilTrue(body func() bool, config *TimeoutConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	bodyChan := make(chan bool, 1)

	asyncBody := func(ch chan bool) {
		success := body()
		ch <- success
		if success {
			close(ch)
		}
	}

	go asyncBody(bodyChan)

	done := time.After(config.Timeout)
	ticker := time.NewTicker(config.Ticker)
	defer ticker.Stop()
	for {
		select {
		case success := <-bodyChan:
			if success {
				return nil
			}
			// Provide some form of rate-limiting here before running next
			// execution in case body() returns at a fast rate.
			select {
			case <-ticker.C:
				go asyncBody(bodyChan)
			}
		case <-done:
			return fmt.Errorf("%s timeout expired", config.Timeout)
		}
	}
}

// WithContext executes body with the given frequency. The function
// f is executed until bool returns true or the given context signalizes Done.
// `f` should stop if context is canceled.
func WithContext(ctx context.Context, f func(ctx context.Context) (bool, error), freq time.Duration) error {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			stop, err := f(ctx)
			if err != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return err
				}
			}
			if stop {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return nil
				}
			}
		}
	}
}

// ReportDirectoryPath returns the directory path for exporting report
// commands in the case of test failure.
func ReportDirectoryPath(testname string) string {
	return filepath.Join(TestResultsPath, testname)
}

// CreateReportDirectory creates and returns the directory path to export all report
// commands that need to be run in the case that a test has failed.
// If the directory cannot be created it'll return an error
func CreateReportDirectory(testname string) (string, error) {
	testPath := ReportDirectoryPath(testname)
	if _, err := os.Stat(testPath); err == nil {
		return testPath, nil
	}
	err := os.MkdirAll(testPath, os.ModePerm)
	return testPath, err
}

// CreateLogFile creates the ReportDirectory if it is not present, writes the
// given data to the given filename.
func CreateLogFile(testname string, filename string, data []byte) error {
	path, err := CreateReportDirectory(testname)
	if err != nil {
		log.WithError(err).Errorf("ReportDirectory cannot be created")
		return err
	}

	finalPath := filepath.Join(path, filename)
	return os.WriteFile(finalPath, data, LogPerm)
}

// WriteToReportFile writes data to filename. It appends to existing files.
func WriteToReportFile(data []byte, testname string, filename string) error {
	testPath, err := CreateReportDirectory(testname)
	if err != nil {
		log.WithError(err).Errorf("cannot create test results path '%s'", testPath)
		return err
	}

	err = WriteOrAppendToFile(
		filepath.Join(testPath, filename),
		data,
		LogPerm)
	if err != nil {
		log.WithError(err).Errorf("cannot create monitor log file %s", filename)
		return err
	}
	return nil
}

// WriteOrAppendToFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm;
// otherwise WriteFile appends the data to the file
func WriteOrAppendToFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func reportMap(path string, reportCmds map[string]string, node *LocalExecutor) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reportMapContext(ctx, path, reportCmds, node)
}

func reportMapContext(ctx context.Context, path string, reportCmds map[string]string, node *LocalExecutor) {
	if node == nil {
		log.Errorf("cannot execute reportMap due invalid node instance")
		return
	}

	for cmd, logfile := range reportCmds {
		res := node.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})
		err := os.WriteFile(
			fmt.Sprintf("%s/%s", path, logfile),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.WithError(err).Errorf("cannot create test results for command '%s'", cmd)
		}
	}
}
