// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Djalal Harouni
// Copyright 2017 Authors of Cilium

package RuntimeTest

import (
	"github.com/linux-lock/bpflock/pkg/logging"
	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger
var logger = logrus.NewEntry(log)
