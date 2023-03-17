// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/exp/slices"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/worker"
	govulncheckapi "golang.org/x/vuln/exp/govulncheck"
)

func Test(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot run on Windows")
	}

	govulncheckPath, err := buildtest.BuildGovulncheck(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	checkVuln := func(t *testing.T, res *govulncheckapi.Result) {
		wantID := "GO-2021-0113"
		i := slices.IndexFunc(res.Vulns, func(v *govulncheckapi.Vuln) bool {
			return v.OSV.ID == wantID
		})
		if i < 0 {
			t.Fatalf("no vuln with ID %s. Result:\n%+v", wantID, res)
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
		resp, err := runTest([]string{govulncheckPath, worker.ModeGovulncheck, module, vulndb})
		if err != nil {
			t.Fatal(err)
		}

		checkVuln(t, &resp.Res)
		if resp.Stats.ScanSeconds <= 0 {
			t.Errorf("got %f; want >0 scan seconds", resp.Stats.ScanSeconds)
		}
		if resp.Stats.ScanMemory <= 0 {
			t.Errorf("got %d; want >0 scan memory", resp.Stats.ScanMemory)
		}
	})

	t.Run("binary", func(t *testing.T) {
		t.Skip("govulncheck may not support the Go version")
		binary := filepath.Join(module, "vuln")
		cmd := exec.Command("go", "build")
		cmd.Dir = module
		if _, err := cmd.Output(); err != nil {
			t.Fatal(derrors.IncludeStderr(err))
		}
		defer os.Remove(binary)
		resp, err := runTest([]string{govulncheckPath, worker.ModeBinary, binary, vulndb})
		if err != nil {
			t.Fatal(err)
		}
		checkVuln(t, &resp.Res)
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
			args: []string{govulncheckPath, worker.ModeGovulncheck, module, "does not exist"},
			want: "does not exist",
		},
		{
			name: "no mode",
			args: []string{govulncheckPath, "MODE", module, vulndb},
			want: "not a valid mode",
		},
		{
			name: "no module",
			args: []string{govulncheckPath, worker.ModeGovulncheck, "nosuchmodule", vulndb},
			want: "no such file",
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
