// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2016-2021 Authors of Cilium

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/rand"

	"github.com/linux-lock/bpflock/api/v1/models"
	. "github.com/linux-lock/bpflock/api/v1/restapi/operations/daemon"
	"github.com/linux-lock/bpflock/pkg/option"
	"github.com/linux-lock/bpflock/pkg/status"
	"github.com/linux-lock/bpflock/pkg/version"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

var randGen = rand.NewSafeRand(time.Now().UnixNano())

type getHealthz struct {
	daemon *Daemon
}

func NewGetHealthzHandler(d *Daemon) GetHealthzHandler {
	return &getHealthz{daemon: d}
}

func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	brief := params.Brief != nil && *params.Brief
	sr := h.daemon.getStatus(brief)

	return NewGetHealthzOK().WithPayload(&sr)
}

// getStatus returns the daemon status. If brief is provided a minimal version
// of the StatusResponse is provided.
func (d *Daemon) getStatus(brief bool) models.StatusResponse {
	staleProbes := d.statusCollector.GetStaleProbes()
	stale := make(map[string]strfmt.DateTime, len(staleProbes))
	for probe, startTime := range staleProbes {
		stale[probe] = strfmt.DateTime(startTime)
	}

	d.statusCollectMutex.RLock()
	defer d.statusCollectMutex.RUnlock()

	var sr models.StatusResponse
	// d.statusResponse contains references, so we do a deep copy to be able to
	// safely use sr after the method has returned
	sr = *d.statusResponse.DeepCopy()

	sr.Stale = stale

	// BpflockVersion definition
	ver := version.GetBpflockVersion()
	bpflockVer := fmt.Sprintf("%s (v%s-%s)", ver.Version, ver.Version, ver.Revision)

	switch {
	case len(sr.Stale) > 0:
		msg := "Stale status data"
		sr.Bpflock = &models.Status{
			State: models.StatusStateWarning,
			Msg:   fmt.Sprintf("%s    %s", bpflockVer, msg),
		}
	default:
		sr.Bpflock = &models.Status{
			State: models.StatusStateOk,
			Msg:   bpflockVer,
		}
	}

	return sr
}

func (d *Daemon) startStatusCollector() {
	probes := []status.Probe{
		{
			Name: "check-locks",
			Probe: func(ctx context.Context) (interface{}, error) {
				// Try to acquire a couple of global locks to have the status API fail
				// in case of a deadlock on these locks
				option.Config.ConfigPatchMutex.Lock()
				option.Config.ConfigPatchMutex.Unlock()
				return nil, nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()
				// FIXME we have no field for the lock status
			},
		},
	}

	d.statusCollector = status.NewCollector(probes, status.Config{})

	return
}
