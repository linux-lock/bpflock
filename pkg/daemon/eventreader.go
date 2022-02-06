// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni

package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/linux-lock/bpflock/bpf/gobpf/bpfevents"
	"github.com/linux-lock/bpflock/bpf/gobpf/bpfrestrict"
	"github.com/linux-lock/bpflock/bpf/gobpf/kimglock"
	"github.com/linux-lock/bpflock/bpf/gobpf/kmodlock"
	"github.com/linux-lock/bpflock/pkg/bpf"
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/linux-lock/bpflock/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func getOperationStr(event *bpfevents.ProcessEvent, str *strings.Builder) {
	var err error
	var op string

	switch event.ProgramId {
	case bpfevents.KimgLockId:
		op, err = kimglock.GetOperationStr(event)
	case bpfevents.KmodLockId:
		op, err = kmodlock.GetOperationStr(event)
	case bpfevents.BpfRestrictId:
		op, err = bpfrestrict.GetOperationStr(event)
	}

	if err == nil && op != "" && op != "(none)" {
		fmt.Fprintf(str, " operation=%s", op)
	}
}

func logEvent(event *bpfevents.ProcessEvent, bpflog *logrus.Entry, str *strings.Builder) {
	if event == nil {
		return
	}

	var ok bool
	data := "N/A"
	program := "N/A"
	str.Reset()

	if event.ProgramId > 0 {
		id := int(event.ProgramId)
		program, ok = bpfevents.ProgramIds[id]
		if !ok {
			program = "N/A"
		}

		id = int(event.EventId)
		data, ok = bpfevents.EventIds[id]
		if !ok {
			data = "N/A"
		}
	}

	fmt.Fprintf(str, "event=%s", data)
	getOperationStr(event, str)

	fmt.Fprintf(str, " tgid=%d pid=%d ppid=%d uid=%d cgroupid=%d",
		event.Tgid, event.Pid, event.Ppid, event.Uid, event.CgroupId)

	if len(event.Comm) > 0 {
		fmt.Fprintf(str, " comm=%s", unix.ByteSliceToString(event.Comm[:]))
	}

	if len(event.Pcomm) > 0 {
		fmt.Fprintf(str, " pcomm=%s", unix.ByteSliceToString(event.Pcomm[:]))
	}

	filename := ""
	if len(event.FileName) > 0 {
		filename = unix.ByteSliceToString(event.FileName[:])
	}

	if len(filename) > 0 {
		fmt.Fprintf(str, " filename=%s", filename)
	}

	fmt.Fprintf(str, " retval=%d", event.ReturnValue)

	if event.Reason > bpfevents.BpflockReasonNone && event.Reason < bpfevents.BpflockMaxReasons {
		id := int(event.Reason)
		r, _ := bpfevents.ReasonStr[id]
		fmt.Fprintf(str, " reason=%s", r)
	}

	bpflog.WithFields(logrus.Fields{
		logfields.LogBpfSubsys: program,
	}).Info(str.String())
}

/* This event reader reads all bpf programs, it operated on shared map */
func readEvents(prog string, r *bpf.RingBufferInfo) {
	var str strings.Builder
	bpflog := logging.DefaultLogger.WithField(logfields.LogSubsys, "bpf")

	if r.Ring == nil {
		bpflog.Warnf("Event reader bpf-map=%s failed invalid buffer", r.Path)
		return
	}

	str.Grow(1024)

	bpflog.Infof("Event reader started on bpf-map=%s", r.Path)

	for {
		record, err := r.Ring.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				bpflog.Infof("Event reader bpf-map=%s received signal, exiting...", r.Path)
				return
			}
			bpflog.WithError(err).Warnf("Event reader bpf-map=%s read failed", r.Path)
			continue
		}

		var event bpfevents.ProcessEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			bpflog.WithError(err).Warnf("Event reader bpf-map=%s parsing bpf event failed", r.Path)
			continue
		}

		logEvent(&event, bpflog, &str)
	}
}

func (d *Daemon) startBpfReadEvents() error {
	for prog, rinfo := range bpf.EventReaders {
		go func(prog string, rinfo *bpf.RingBufferInfo) {
			readEvents(prog, rinfo)
		}(prog, rinfo)
	}

	return nil
}
