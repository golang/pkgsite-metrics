// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/exp/slices"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
)

func Test(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot run on Windows")
	}
	if testing.Short() {
		t.Skip("skipping test that uses internet in short mode")
	}

	govulncheckPath, err := buildtest.BuildGovulncheck(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	checkVuln := func(t *testing.T, findings []*govulncheckapi.Finding) {
		wantID := "GO-2021-0113"
		i := slices.IndexFunc(findings, func(f *govulncheckapi.Finding) bool {
			return f.OSV == wantID
		})
		if i < 0 {
			t.Fatalf("no vuln with ID %s. Result:\n%+v", wantID, findings)
		}
	}

	testData := "../../internal/testdata"
	module := filepath.Join(testData, "module")
	// govulncheck binary requires a full path to the vuln db. Otherwise, one
	// gets "[file://testdata/vulndb], opts): file URL specifies non-local host."
	vulndb, err := filepath.Abs(filepath.Join(testData, "vulndb"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("source", func(t *testing.T) {
		resp, err := runTest([]string{govulncheckPath, govulncheck.FlagSource, module, vulndb})
		if err != nil {
			t.Fatal(err)
		}

		checkVuln(t, resp.Findings)
		if resp.Stats.ScanSeconds <= 0 {
			t.Errorf("got %f; want >0 scan seconds", resp.Stats.ScanSeconds)
		}
		if resp.Stats.ScanMemory <= 0 {
			t.Errorf("got %d; want >0 scan memory", resp.Stats.ScanMemory)
		}
	})

	// Errors
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "too few args",
			args: []string{"testdata/module", vulndb},
			want: "need four args",
		},
		{
			name: "no vulndb",
			args: []string{govulncheckPath, govulncheck.FlagSource, module, "DNE"},
			want: "URL missing path",
		},
		{
			name: "no mode",
			args: []string{govulncheckPath, "unsupported mode", module, vulndb},
			want: "not a valid mode",
		},
		{
			name: "no mode",
			args: []string{govulncheckPath, govulncheck.FlagBinary, module, vulndb},
			want: "binaries are only analyzed",
		},
		{
			name: "no module",
			args: []string{govulncheckPath, govulncheck.FlagSource, "nosuchmodule", vulndb},
			// Once govulncheck destinguishes this issue from no .mod file,
			// update want to reflect govulncheck's new output
			want: "no go.mod",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := runTest(test.args)
			if err == nil {
				t.Fatal("got nil, want error")
			}
			if g, w := err.Error(), test.want; !strings.Contains(g, w) {
				t.Fatalf("error %q does not contain %q", g, w)
			}
		})
	}
}

func runTest(args []string) (*govulncheck.SandboxResponse, error) {
	var buf bytes.Buffer
	run(&buf, args)
	return govulncheck.UnmarshalSandboxResponse(buf.Bytes())
}
