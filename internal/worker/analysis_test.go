// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestRunAnalysisBinary(t *testing.T) {
	binPath := buildtest.GoBuild(t, "testdata/analyzer", "")

	got, err := runAnalysisBinary(nil, binPath, "-name Fact ./...", "testdata/module")
	if err != nil {
		t.Fatal(err)
	}
	want := analysis.JSONTree{
		"test_module": map[string]analysis.DiagnosticsOrError{
			"findcall": analysis.DiagnosticsOrError{
				Diagnostics: []analysis.JSONDiagnostic{
					{
						Posn:    "a.go:7:17",
						Message: "call of Fact(...)",
						SuggestedFixes: []analysis.JSONSuggestedFix{
							{
								Message: "Add '_TEST_'",
								Edits: []analysis.JSONTextEdit{{
									Filename: "a.go",
									Start:    77,
									End:      77,
									New:      "_TEST_",
								}},
							},
						},
					},
				},
			},
		},
	}
	// To make the test portable, compare the basenames of file paths.
	// This will be called for all strings, but in this case only file paths contain slashes.
	comparePaths := func(s1, s2 string) bool {
		return filepath.Base(s1) == filepath.Base(s2)
	}

	if diff := cmp.Diff(want, got, cmp.Comparer(comparePaths)); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestCreateAnalysisQueueTasks(t *testing.T) {
	mods := []scan.ModuleSpec{
		{Path: "a.com/a", Version: "v1.2.3", ImportedBy: 1},
		{Path: "b.com/b", Version: "v1.0.0", ImportedBy: 2},
	}
	got := createAnalysisQueueTasks(&analysis.EnqueueParams{
		Binary:   "bin",
		Args:     "args",
		Insecure: true,
		Suffix:   "suff",
	}, "jobID", "binVersion", mods)
	want := []queue.Task{
		&analysis.ScanRequest{
			ModuleURLPath: scan.ModuleURLPath{Module: "a.com/a", Version: "v1.2.3"},
			ScanParams: analysis.ScanParams{
				Binary:        "bin",
				BinaryVersion: "binVersion",
				Args:          "args",
				ImportedBy:    1,
				Insecure:      true,
				JobID:         "jobID",
			},
		},
		&analysis.ScanRequest{
			ModuleURLPath: scan.ModuleURLPath{Module: "b.com/b", Version: "v1.0.0"},
			ScanParams: analysis.ScanParams{
				Binary:        "bin",
				BinaryVersion: "binVersion",
				Args:          "args",
				ImportedBy:    2,
				Insecure:      true,
				JobID:         "jobID",
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestAnalysisScan(t *testing.T) {
	test.NeedsIntegrationEnv(t)
	const (
		modulePath = "golang.org/x/scratch/kusano/replacement"
		version    = "v0.0.0-20250813163312-416cbb1e76e6"
	)
	binaryPath := buildtest.GoBuild(t, "testdata/analyzer", "")
	proxyClient, err := proxy.New("https://proxy.golang.org/cached-only")
	if err != nil {
		t.Fatal(err)
	}

	diff := func(want, got *analysis.Result) {
		t.Helper()
		d := cmp.Diff(want, got,
			cmpopts.IgnoreFields(analysis.Diagnostic{}, "Position", "Source"))
		if d != "" {
			t.Errorf("mismatch (-want, +got)\n%s", d)
		}
	}

	s := &analysisServer{
		Server: &Server{
			proxyClient: proxyClient,
			cfg: &config.Config{
				BinaryBucket: "unused",
				BinaryDir:    t.TempDir(),
			},
		},
	}
	req := &analysis.ScanRequest{
		ModuleURLPath: scan.ModuleURLPath{Module: modulePath, Version: version},
		ScanParams: analysis.ScanParams{
			Binary:   "analyzer",
			Args:     "-name GenerateFromPassword",
			Insecure: true,
			JobID:    "jid",
			NoDeps:   false,
			SkipInit: true,
		},
	}
	wv := analysis.WorkVersion{BinaryArgs: "-name GenerateFromPassword", BinaryVersion: "bv", SchemaVersion: "sv"}
	got := s.scan(context.Background(), req, binaryPath, wv)
	commitTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", "2025-08-13 16:33:12 +0000 UTC")
	if err != nil {
		t.Fatal(err)
	}
	want := &analysis.Result{
		ModulePath:    modulePath,
		Version:       version,
		SortVersion:   "0,0,0,~20250813163312-416cbb1e76e6",
		CommitTime:    commitTime,
		JobID:         "jid",
		BinaryName:    "analyzer",
		WorkVersion:   wv,
		Error:         "",
		ErrorCategory: "",
		Diagnostics: []*analysis.Diagnostic{
			{
				PackageID:    "golang.org/x/scratch/kusano/replacement",
				AnalyzerName: "findcall",
				Message:      "call of GenerateFromPassword(...)",
				Source:       bq.NullString{},
			},
		},
	}
	diff(want, got)

	// Test that errors are put into the Result.
	req.Binary = "bad"
	got = s.scan(context.Background(), req, "yyy", wv)
	// Trim varying part of error. The error is expected to be of the form
	// "...executable file not found in $PATH: scan synthetic module error."
	if i := strings.LastIndexByte(got.Error, ':'); i > 0 {
		got.Error = got.Error[:i]
		if i := strings.LastIndexByte(got.Error, ':'); i > 0 {
			got.Error = got.Error[i+2:]
		}
	}
	// And the platform-specific part.
	if i := strings.LastIndex(got.Error, "not found in"); i > 0 {
		got.Error = got.Error[:i+len("not found in")]
	}

	want = &analysis.Result{
		ModulePath:    modulePath,
		Version:       version,
		SortVersion:   "0,0,0,~20250813163312-416cbb1e76e6",
		JobID:         "jid",
		BinaryName:    "bad",
		WorkVersion:   wv,
		ErrorCategory: "SYNTHETIC - MISC",
		Error:         "executable file not found in",
	}
	diff(want, got)
}

func TestParsePosition(t *testing.T) {
	for _, test := range []struct {
		pos      string
		wantFile string
		wantLine int
		wantCol  int
		wantErr  bool
	}{
		{"", "", 0, 0, true},
		{"x", "", 0, 0, true},
		{"x/y:b:1", "", 0, 0, true},
		{"x/y:17:2", "x/y", 17, 2, false},
		{"x:y:z:973:3", "x:y:z", 973, 3, false},
	} {
		gotFile, gotLine, gotCol, err := parsePosition(test.pos)
		gotErr := err != nil
		if gotFile != test.wantFile || gotLine != test.wantLine || gotCol != test.wantCol || gotErr != test.wantErr {
			t.Errorf("got (%q, %d, %d, %t), want (%q, %d, %d, %t)",
				gotFile, gotLine, gotCol, gotErr,
				test.wantFile, test.wantLine, test.wantCol, test.wantErr)
		}
	}
}

func TestReadSource(t *testing.T) {
	// Create a file with five lines containing the numbers 1 through 5.
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, []byte("1\n2\n3\n4\n5\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		line     int
		nContext int
		want     string
	}{
		// line number out of range -> empty string
		{-1, 0, ""},
		{6, 0, ""},
		{1, 0, "1"},
		{1, 1, "1\n2"},
		{2, 1, "1\n2\n3"},
		{4, 2, "2\n3\n4\n5"},
	} {
		t.Run(fmt.Sprintf("line:%d,nc:%d", test.line, test.nContext), func(t *testing.T) {
			got, err := readSource(file, test.line, test.nContext)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := got, test.want; g != w {
				t.Errorf("got\n%s\nwant\n%s", g, w)
			}
		})
	}
}
