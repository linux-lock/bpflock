// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2020 Authors of Cilium

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/linux-lock/bpflock/api/v1/models"
	"github.com/linux-lock/bpflock/pkg/option"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// startAgentHealthHTTPService registers a handler function for the /healthz status HTTP endpoint
// exposed on localhost (127.0.0.1 and/or ::1, depending on IPv4/IPv6 options). This
// endpoint reports the agent health status.
func (d *Daemon) startAgentHealthHTTPService() {
	var hosts []string
	if option.Config.IPv4Enabled() {
		hosts = append(hosts, "127.0.0.1")
	}
	if option.Config.IPv6Enabled() {
		hosts = append(hosts, "::1")
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isUnhealthy := func(sr *models.StatusResponse) bool {
			if sr.Bpflock != nil {
				state := sr.Bpflock.State
				return state != models.StatusStateOk && state != models.StatusStateDisabled
			}
			return false
		}
		statusCode := http.StatusOK
		sr := d.getStatus(true)
		if isUnhealthy(&sr) {
			statusCode = http.StatusServiceUnavailable
		}

		w.WriteHeader(statusCode)
	}))

	available := len(hosts)
	for _, host := range hosts {
		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", option.Config.AgentHealthPort))
		addrField := logrus.Fields{"address": addr}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if errors.Is(err, unix.EADDRNOTAVAIL) {
			log.WithFields(addrField).Info("healthz status API server not available")
			available--
			continue
		} else if err != nil {
			log.WithFields(addrField).WithError(err).Fatal("Unable to start healthz status API server")
		}

		go func(addr string, ln net.Listener) {
			srv := &http.Server{
				Addr:    addr,
				Handler: mux,
			}
			err := srv.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) {
				log.WithFields(addrField).Info("healthz status API server shutdown")
			} else if err != nil {
				log.WithFields(addrField).WithError(err).Fatal("Error serving healthz status API server")
			}
		}(addr, ln)
		log.WithFields(addrField).Info("Started healthz status API server")
	}

	if available <= 0 {
		log.WithField("hosts", hosts).Fatal("No healthz status API server started")
	}
}
