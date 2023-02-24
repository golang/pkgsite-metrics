// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/exp/slices"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/worker"
	"golang.org/x/vuln/vulncheck"
)

func Test(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot run on Windows")
	}

	checkVuln := func(t *testing.T, res *vulncheck.Result) {
		wantID := "GO-2021-0113"
		i := slices.IndexFunc(res.Vulns, func(v *vulncheck.Vuln) bool {
			return v.OSV.ID == wantID
		})
		if i < 0 {
			t.Fatalf("no vuln with ID %s. Result:\n%+v", wantID, res)
		}
	}

	t.Run("source", func(t *testing.T) {
		res, err := runTest([]string{worker.ModeVTA, "testdata/module"}, "testdata/vulndb")
		if err != nil {
			t.Fatal(err)
		}
		checkVuln(t, res)
	})

	t.Run("binary", func(t *testing.T) {
		t.Skip("vulncheck.Binary may not support the Go version")
		const binary = "testdata/module/vuln"
		cmd := exec.Command("go build")
		cmd.Dir = "testdata/module"
		if _, err := cmd.Output(); err != nil {
			t.Fatal(derrors.IncludeStderr(err))
		}
		defer os.Remove(binary)
		res, err := runTest([]string{worker.ModeBinary, binary}, "testdata/vulndb")
		if err != nil {
			t.Fatal(err)
		}
		checkVuln(t, res)
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
			vulndb: "testdata/vulndb",
			want:   "need two args",
		},
		{
			name:   "no vulndb",
			args:   []string{worker.ModeVTA, "testdata/module"},
			vulndb: "does not exist",
			want:   "no such file",
		},
		{
			name:   "no mode",
			args:   []string{"MODE", "testdata/module"},
			vulndb: "testdata/vulndb",
			want:   "not a valid mode",
		},
		{
			name:   "no module",
			args:   []string{worker.ModeVTA, "testdata/nosuchmodule"},
			vulndb: "testdata/vulndb",
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

func runTest(args []string, vulndbDir string) (*vulncheck.Result, error) {
	var buf bytes.Buffer
	run(&buf, args, vulndbDir)
	return unmarshalVulncheckOutput(buf.Bytes())
}

func unmarshalVulncheckOutput(output []byte) (*vulncheck.Result, error) {
	var e struct {
		Error string
	}
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res vulncheck.Result
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
