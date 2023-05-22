// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"golang.org/x/exp/maps"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	"golang.org/x/pkgsite-metrics/internal/osv"
)

// NewMetricsHandler returns a handler that returns a set of all findings.
// For use in the ecosystem metrics pipeline.
func NewMetricsHandler() *MetricsHandler {
	m := make(map[string]*govulncheckapi.Finding)
	return &MetricsHandler{
		byOSV: m,
	}
}

type MetricsHandler struct {
	byOSV map[string]*govulncheckapi.Finding
}

func (h *MetricsHandler) Config(c *govulncheckapi.Config) error {
	return nil
}

func (h *MetricsHandler) Progress(p *govulncheckapi.Progress) error {
	return nil
}

func (h *MetricsHandler) OSV(e *osv.Entry) error {
	return nil
}

func (h *MetricsHandler) Finding(finding *govulncheckapi.Finding) error {
	f, found := h.byOSV[finding.OSV]
	if !found || f.Trace[0].Function == "" {
		// If the vuln wasn't called in the first trace, replace it with
		// the new finding (that way if the vuln is called at any point
		// it's trace will reflect that, which is needed when converting to bq)
		h.byOSV[finding.OSV] = finding
	}
	return nil
}

func (h *MetricsHandler) Findings() []*govulncheckapi.Finding {
	return maps.Values(h.byOSV)
}
