// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	ivulncheck "golang.org/x/pkgsite-metrics/internal/vulncheck"
)

func TestVulnsScanned(t *testing.T) {
	p := newPage("test")

	vuln1A := &ivulncheck.Vuln{ID: "1", Symbol: "A", CallSink: bigquery.NullInt(100)}
	vuln1B := &ivulncheck.Vuln{ID: "1", Symbol: "B", CallSink: bigquery.NullInt(101)}
	vuln1C := &ivulncheck.Vuln{ID: "1", Symbol: "C"}
	vuln2A := &ivulncheck.Vuln{ID: "2", Symbol: "A"}

	rows := []*ivulncheck.Result{
		{ModulePath: "m1", ScanMode: ModeImports, Vulns: []*ivulncheck.Vuln{vuln1A, vuln1B, vuln1C, vuln2A}},
		{ModulePath: "m1", ScanMode: ModeVTAStacks, Vulns: []*ivulncheck.Vuln{vuln1A, vuln1B}},
		{ModulePath: "m2", ScanMode: ModeImports, Vulns: []*ivulncheck.Vuln{vuln2A}},
		{ModulePath: "m2", ScanMode: ModeVTAStacks, Vulns: []*ivulncheck.Vuln{}},
	}

	got := handleVulncheckRows(context.Background(), p, rows)
	// Vuln 1 is detected in m1 module in both IMPORTS and VTA modes.
	// Vuln 2 is detected in m1 and m2 in IMPORTS mode, but nowhere
	// in VTA mode.
	want := map[string]*ReportResult{
		"1": &ReportResult{ImportsNumModules: 1, VTANumModules: 1},
		"2": &ReportResult{ImportsNumModules: 2, VTANumModules: 0},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
