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

	// Remove any old bpf programs
	bpf.BpfLsmDisable()

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

	/* TODO Load configuration and bpf related options */

	err = bpf.ConfigureResourceLimits()
	if err != nil {
		log.WithError(err).Fatal("Unable to set memory resource limits")
	}

	d := Daemon{
		ctx:    ctx,
		cancel: cancel,
	}

	d.configModifyQueue = eventqueue.NewEventQueueBuffered("config-modify-queue", ConfigModifyQueueSize)
	d.configModifyQueue.Run()

	// Delete BPF programs on exit if running in tandem with Flannel.
	/*if option.Config.FlannelUninstallOnExit {
		cleaner.cleanupFuncs.Add(func() {
			for _, ep := range d.endpointManager.GetEndpoints() {
				ep.DeleteBPFProgramLocked()
			}
		})
	}
	*/

	return &d, nil
}

// Close shuts down a daemon
func (d *Daemon) Close() {
}

// TriggerReloadWithoutCompile causes all BPF programs and maps to be reloaded,
// without recompiling the datapath logic for each endpoint. It first attempts
// to recompile the base programs, and if this fails returns an error. If base
// program load is successful, it subsequently triggers regeneration of all
// endpoints and returns a waitgroup that may be used by the caller to wait for
// all endpoint regeneration to complete.
//
// If an error is returned, then no regeneration was successful. If no error
// is returned, then the base programs were successfully regenerated, but
// endpoints may or may not have successfully regenerated.
/*func (d *Daemon) TriggerReloadWithoutCompile(reason string) (*sync.WaitGroup, error) {
	log.Debugf("BPF reload triggered from %s", reason)
	if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
		return nil, fmt.Errorf("Unable to recompile base programs from %s: %s", reason, err)
	}

	regenRequest := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapathLoad,
	}
	return d.endpointManager.RegenerateAllEndpoints(regenRequest), nil
}
*/

func changedOption(key string, value option.OptionSetting, data interface{}) {
	d := data.(*Daemon)
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		if d.DebugEnabled() {
			logging.SetLogLevelToDebug()
		}
	}
}
