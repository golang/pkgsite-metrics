// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
)

func TestAsScanError(t *testing.T) {
	check := func(err error, want bool) {
		if got := errors.As(err, new(scanError)); got != want {
			t.Errorf("%T: got %t, want %t", err, got, want)
		}
	}
	check(io.EOF, false)
	check(scanError{io.EOF}, true)
}

func TestVulnsForMode(t *testing.T) {
	findings := []*govulncheckapi.Finding{
		{Trace: []*govulncheckapi.Frame{{Module: "M1", Package: "P1", Function: "F1"}}},
		{Trace: []*govulncheckapi.Frame{{Module: "M1", Package: "P1"}}},
		{Trace: []*govulncheckapi.Frame{{Module: "M1"}}},
		{Trace: []*govulncheckapi.Frame{{Module: "M2"}}},
	}

	vulnsStr := func(vulns []*govulncheck.Vuln) string {
		var vs []string
		for _, v := range vulns {
			vs = append(vs, fmt.Sprintf("%s:%s", v.ModulePath, v.PackagePath))
		}
		return strings.Join(vs, ", ")
	}

	for _, tc := range []struct {
		mode string
		want string
	}{
		{scanModeSourceSymbol, "M1:P1"},
		{scanModeSourcePackage, "M1:P1"},
		{scanModeSourceModule, "M1:, M2:"},
	} {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			vs := vulnsForScanMode(&govulncheck.AnalysisResponse{Findings: findings}, tc.mode)
			if got := vulnsStr(vs); got != tc.want {
				t.Errorf("got %s; want %s", got, tc.want)
			}
		})
	}
}

func TestUnrecoverableError(t *testing.T) {
	for _, e := range []struct {
		ec   string
		want bool
	}{
		{"LOAD", true},
		{"MISC", false},
		{"BIGQUERY", false},
	} {
		if got := unrecoverableError(e.ec); got != e.want {
			t.Errorf("want %t for %s; got %t", e.want, e.ec, got)
		}
	}
}

// TODO: can we have a test for sandbox? We do test the sandbox
// and unmarshalling in cmd/govulncheck_sandbox, so what would be
// left here is checking that runsc is initiated properly. It is
// not clear how to do that here nor is it necessary.
func TestRunScanModuleInsecure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that uses internet in short mode")
	}

	govulncheckPath, err := buildtest.BuildGovulncheck(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	vulndb, err := filepath.Abs("../testdata/vulndb")
	if err != nil {
		t.Fatal(err)
	}

	s := &scanner{insecure: true, govulncheckPath: govulncheckPath, vulnDBDir: vulndb}

	response, err := s.runGovulncheckScanInsecure("../testdata/module", ModeGovulncheck)
	if err != nil {
		t.Fatal(err)
	}
	findings := response.Findings
	wantID := "GO-2021-0113"
	found := false
	for _, v := range findings {
		if v.OSV == wantID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("want %s, did not find it in %d vulns", wantID, len(findings))
	}

	stats := response.Stats
	if got := stats.ScanSeconds; got <= 0 {
		t.Errorf("scan time not collected or negative: %v", got)
	}
	if got := stats.ScanMemory; got <= 0 && runtime.GOOS == "linux" {
		t.Errorf("scan memory not collected or negative: %v", got)
	}
}
