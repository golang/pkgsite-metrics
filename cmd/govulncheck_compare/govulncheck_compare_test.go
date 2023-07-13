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

	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
)

func Test(t *testing.T) {
	// TODO: Modify test to ensure that govulncheck & the built binaries are all
	// built with the same version of go. Test currently fails on cloudtop machines
	// because go versions are different.
	// govulncheck_compare works in integration testing, as binaries are built in
	// the sandbox which ensures that the go versions are the same
	t.Skip("Govulncheck fails on binaries built with Go versions 12.1+, which cloudtop is ran on")
	if runtime.GOOS == "windows" {
		t.Skip("cannot run on Windows")
	}

	govulncheckPath, err := buildtest.BuildGovulncheck(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	testData := "../../internal/testdata"
	module := filepath.Join(testData, "module")

	// govulncheck binary requires a full path to the vuln db. Otherwise, one
	// gets "[file://testdata/vulndb], opts): file URL specifies non-local host."
	vulndb, err := filepath.Abs(filepath.Join(testData, "vulndb"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("basicComparison", func(t *testing.T) {
		resp, err := runTest([]string{govulncheckPath, module, vulndb})
		if err != nil {
			t.Fatal(err)
		}

		pair := resp.FindingsForMod["golang.org/vuln"]
		t.Log(pair)
		// TODO: concretely test that the results are as expected.
	})

}

func runTest(args []string) (*govulncheck.CompareResponse, error) {
	var buf bytes.Buffer
	run(&buf, args)
	return govulncheck.UnmarshalCompareResponse(buf.Bytes())
}
