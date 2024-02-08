// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	"golang.org/x/pkgsite-metrics/internal/osv"
)

// NewMetricsHandler returns a handler that returns all findings.
// For use in the ecosystem metrics pipeline.
func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{}
}

type MetricsHandler struct {
	findings []*govulncheckapi.Finding
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
	h.findings = append(h.findings, finding)
	return nil
}

func (h *MetricsHandler) Findings() []*govulncheckapi.Finding {
	return h.findings
}
