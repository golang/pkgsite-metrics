// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"testing"

	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
)

func TestMetricsHandler(t *testing.T) {
	osvID := "GO-YYYY-XXXX"
	calledFinding := &govulncheckapi.Finding{
		OSV: osvID,
		Trace: []*govulncheckapi.Frame{
			{
				Module:   "example.com/repo/module",
				Version:  "v0.0.1",
				Package:  "example.com/repo/module/package",
				Function: "func",
				Position: &govulncheckapi.Position{},
			},
		},
	}

	uncalledFinding := &govulncheckapi.Finding{
		OSV:          osvID,
		FixedVersion: "",
		Trace: []*govulncheckapi.Frame{
			{
				Module:   "example.com/repo/module",
				Version:  "v0.0.1",
				Package:  "example.com/repo/module/package",
				Position: nil,
			},
		},
	}

	t.Run("Called finding overwrites uncalled w/ same ID", func(t *testing.T) {
		h := NewMetricsHandler()
		h.Finding(uncalledFinding)
		h.Finding(calledFinding)
		findings := h.Findings()
		if len(findings) != 1 || findings[0] != calledFinding {
			t.Errorf("MetricsHandler.Finding() error: expected %v, got %v", calledFinding, findings[0])
		}
	})
}
