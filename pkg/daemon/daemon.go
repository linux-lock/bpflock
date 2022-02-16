// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2021 Authors of Cilium

package daemon

import (
	"context"
	"fmt"
	"os"

	"github.com/linux-lock/bpflock/api/v1/models"
	"github.com/linux-lock/bpflock/pkg/bpf"
	"github.com/linux-lock/bpflock/pkg/defaults"
	"github.com/linux-lock/bpflock/pkg/eventqueue"
	"github.com/linux-lock/bpflock/pkg/lock"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"
	"github.com/linux-lock/bpflock/pkg/option"
	"github.com/linux-lock/bpflock/pkg/status"
)

const (
	// ConfigModifyQueueSize is the size of the event queue for serializing
	// configuration updates to the daemon
	ConfigModifyQueueSize = 10
)

// Daemon is the daemon that is in charge of perform all necessary security
// locking and auditing mechanisms.
type Daemon struct {
	ctx    context.Context
	cancel context.CancelFunc

	statusCollectMutex lock.RWMutex
	statusResponse     models.StatusResponse
	statusCollector    *status.Collector

	// event queue for serializing configuration updates to the daemon.
	configModifyQueue *eventqueue.EventQueue
}

// DebugEnabled returns if debug mode is enabled.
func (d *Daemon) DebugEnabled() bool {
	return option.Config.Opts.IsEnabled(option.Debug)
}

// GetOptions returns the datapath configuration options of the daemon.
func (d *Daemon) GetOptions() *option.IntOptions {
	return option.Config.Opts
}

func (d *Daemon) init() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}

	if err := os.Chdir(option.Config.StateDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.StateDir).Fatal("Could not change to runtime directory")
	}

	// Let's apply system settings
	applySystemSettings()

	// Start all bpf programs
	if err := bpf.BpfLsmEnable(); err != nil {
		// make sure to disable all bpf programs on failures
		bpf.BpfLsmDisable()
		return err
	}

	return nil
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(ctx context.Context, cancel context.CancelFunc) (*Daemon, error) {

	// Pass the cancel to our signal handler directly so that it's canceled
	// before we run the cleanup functions (see `cleanup.go` for implementation).
	cleaner.SetCancelFunc(cancel)

	// Validate the daemon-specific global options.
	err := option.Config.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid daemon configuration: %s", err)
	}

	err = bpf.ConfigureResourceLimits()
	if err != nil {
		log.WithError(err).Fatal("Unable to set memory resource limits")
	}

	// Remove any previous old bpf programs
	bpf.BpfLsmDisable()

	d := Daemon{
		ctx:    ctx,
		cancel: cancel,
	}

	d.configModifyQueue = eventqueue.NewEventQueueBuffered("config-modify-queue", ConfigModifyQueueSize)
	d.configModifyQueue.Run()

	if option.Config.RmBpfOnExit {
		cleaner.cleanupFuncs.Add(func() {
			bpf.BpfLsmDisable()
		})
	}

	// Always destroy embedded Programs
	cleaner.cleanupFuncs.Add(func() {
		bpf.DestroyEmbeddedProgs()
	})

	err = d.init()
	if err != nil {
		return nil, fmt.Errorf("error while initializing daemon: %w", err)
	}

	return &d, nil
}

// Close shuts down a daemon
func (d *Daemon) Close() {
}

func changedOption(key string, value option.OptionSetting, data interface{}) {
	d := data.(*Daemon)
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		if d.DebugEnabled() {
			logging.SetLogLevelToDebug()
		}
	}
}
