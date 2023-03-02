// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

func TestRunAnalysisBinary(t *testing.T) {
	const binary = "./analyzer"
	binaryPath, cleanup := buildtest.GoBuild(t, "testdata/analyzer", "")
	defer cleanup()

	got, err := runAnalysisBinary(nil, binaryPath, "-name Fact", "testdata/module")
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
	}, mods)
	want := []queue.Task{
		&analysis.ScanRequest{
			ModuleURLPath: scan.ModuleURLPath{Module: "a.com/a", Version: "v1.2.3"},
			ScanParams: analysis.ScanParams{Binary: "bin", Args: "args",
				ImportedBy: 1, Insecure: true},
		},
		&analysis.ScanRequest{
			ModuleURLPath: scan.ModuleURLPath{Module: "b.com/b", Version: "v1.0.0"},
			ScanParams: analysis.ScanParams{Binary: "bin", Args: "args",
				ImportedBy: 2, Insecure: true},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
