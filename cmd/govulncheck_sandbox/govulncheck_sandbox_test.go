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

	tempDir, err := os.MkdirTemp("", "installGovulncheck")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatal(err)
		}
	}()

	govulncheckPath, err := buildtest.BuildGovulncheck(tempDir)
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

	// govulncheck binary requires a full path to the vuln db. Otherwise, one
	// gets "[file://testdata/vulndb], opts): file URL specifies non-local host."
	vulndb, err := filepath.Abs("testdata/vulndb")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("source", func(t *testing.T) {
		resp, err := runTest([]string{govulncheckPath, worker.ModeGovulncheck, "testdata/module"}, vulndb)
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
		const binary = "testdata/module/vuln"
		cmd := exec.Command("go build")
		cmd.Dir = "testdata/module"
		if _, err := cmd.Output(); err != nil {
			t.Fatal(derrors.IncludeStderr(err))
		}
		defer os.Remove(binary)
		resp, err := runTest([]string{govulncheckPath, worker.ModeBinary, binary}, vulndb)
		if err != nil {
			t.Fatal(err)
		}
		checkVuln(t, &resp.Res)
	})

	// Errors
	for _, test := range []struct {
		name   string
		args   []string
		vulndb string
		want   string
	}{
		{
			name:   "too few args",
			args:   []string{"testdata/module"},
			vulndb: vulndb,
			want:   "need three args",
		},
		{
			name:   "no vulndb",
			args:   []string{govulncheckPath, worker.ModeGovulncheck, "testdata/module"},
			vulndb: "does not exist",
			want:   "exit status 1",
		},
		{
			name:   "no mode",
			args:   []string{govulncheckPath, "MODE", "testdata/module"},
			vulndb: vulndb,
			want:   "not a valid mode",
		},
		{
			name:   "no module",
			args:   []string{govulncheckPath, worker.ModeGovulncheck, "testdata/nosuchmodule"},
			vulndb: vulndb,
			want:   "no such file",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := runTest(test.args, test.vulndb)
			if err == nil {
				t.Fatal("got nil, want error")
			}
			if g, w := err.Error(), test.want; !strings.Contains(g, w) {
				t.Fatalf("error %q does not contain %q", g, w)
			}
		})
	}
}

func runTest(args []string, vulndbDir string) (*govulncheck.SandboxResponse, error) {
	var buf bytes.Buffer
	run(&buf, args, vulndbDir)
	return govulncheck.UnmarshalSandboxResponse(buf.Bytes())
}
