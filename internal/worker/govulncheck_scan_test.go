// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	test "golang.org/x/pkgsite-metrics/internal/testing"
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
	vulns := []*govulncheck.Vuln{
		&govulncheck.Vuln{ID: "A"},
		&govulncheck.Vuln{ID: "B", Called: false},
		&govulncheck.Vuln{ID: "C", Called: true},
	}

	vulnsStr := func(vulns []*govulncheck.Vuln) string {
		var vs []string
		for _, v := range vulns {
			vs = append(vs, fmt.Sprintf("%s:%t", v.ID, v.Called))
		}
		return strings.Join(vs, ", ")
	}

	for _, tc := range []struct {
		mode string
		want string
	}{
		{modeImports, "A:false, B:false, C:false"},
		{ModeGovulncheck, "C:true"},
		{ModeBinary, "A:false, B:false, C:true"},
	} {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			modeVulns := vulnsForMode(vulns, tc.mode)
			if got := vulnsStr(modeVulns); got != tc.want {
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

	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		input string
		mode  string
	}{
		{"source", "../testdata/module", ModeGovulncheck},
		// test_vuln binary on gcs is built from ../testdata/module.
		{"binary", "test_vuln", ModeBinary},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := &scanner{insecure: true, govulncheckPath: govulncheckPath, vulnDBDir: vulndb}

			if tc.mode == ModeBinary {
				test.NeedsIntegrationEnv(t)

				gcsClient, err := storage.NewClient(ctx)
				if err != nil {
					t.Fatal(err)
				}
				s.gcsBucket = gcsClient.Bucket("go-ecosystem")
			}

			stats := &govulncheck.ScanStats{}
			findings, err := s.runGovulncheckScanInsecure(ctx,
				"golang.org/vuln", "v0.0.0",
				tc.input, tc.mode, stats)
			if err != nil {
				t.Fatal(err)
			}
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
			if got := stats.ScanSeconds; got <= 0 {
				t.Errorf("scan time not collected or negative: %v", got)
			}
			if got := stats.ScanMemory; got <= 0 && runtime.GOOS == "linux" {
				t.Errorf("scan memory not collected or negative: %v", got)
			}
		})
	}
}
