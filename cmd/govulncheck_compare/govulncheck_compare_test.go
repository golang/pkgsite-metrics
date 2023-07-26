// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for the govulncheck_compare binary

package main

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
)

func Test(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot run on Windows")
	}

	govulncheckPath, err := buildtest.BuildGovulncheck(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	testData := "../../internal/testdata"

	// govulncheck binary requires a full path to the vuln db. Otherwise, one
	// gets "[file://testdata/vulndb], opts): file URL specifies non-local host."
	vulndb, err := filepath.Abs(filepath.Join(testData, "vulndb"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("basicComparison", func(t *testing.T) {
		resp, err := runTest([]string{govulncheckPath, filepath.Join(testData, "module"), vulndb})
		if err != nil {
			t.Fatal(err)
		}

		compareSameFindings(t, resp)
	})

	t.Run("multipleComparison", func(t *testing.T) {
		resp, err := runTest([]string{govulncheckPath, filepath.Join(testData, "multipleBinModule"), vulndb})
		if err != nil {
			t.Fatal(err)
		}

		compareSameFindings(t, resp)
	})
}

func compareSameFindings(t *testing.T, resp *govulncheck.CompareResponse) {
	for path, pair := range resp.FindingsForMod {
		diff := cmp.Diff(pair.BinaryResults.Findings, pair.SourceResults.Findings, cmpopts.SortSlices(
			func(x, y *govulncheckapi.Finding) bool {
				return x.OSV < y.OSV
			}),
			cmpopts.IgnoreFields(govulncheckapi.Finding{}, "Trace"),
		)
		if diff != "" {
			t.Errorf("mismatch for %s (-Binary, +Source): %s", path, diff)
		}
	}
}

func runTest(args []string) (*govulncheck.CompareResponse, error) {
	var buf bytes.Buffer
	run(&buf, args)
	return govulncheck.UnmarshalCompareResponse(buf.Bytes())
}
