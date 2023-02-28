// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/buildtest"
)

func TestRunAnalysisBinary(t *testing.T) {
	const binary = "./analyzer"
	binaryPath, cleanup := buildtest.GoBuild(t, "testdata/analyzer", "")
	defer cleanup()

	got, err := runAnalysisBinary(nil, binaryPath, "-name Fact", "testdata/module")
	if err != nil {
		t.Fatal(err)
	}
	want := JSONTree{
		"test_module": map[string]diagnosticsOrError{
			"findcall": diagnosticsOrError{
				Diagnostics: []JSONDiagnostic{
					{
						Posn:    "a.go:7:17",
						Message: "call of Fact(...)",
						SuggestedFixes: []JSONSuggestedFix{
							{
								Message: "Add '_TEST_'",
								Edits: []JSONTextEdit{{
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

func TestJSONTreeToDiagnostics(t *testing.T) {
	in := JSONTree{
		"pkg1": {
			"a": {
				Diagnostics: []JSONDiagnostic{
					{Category: "c1", Posn: "pos1", Message: "m1"},
					{Category: "c2", Posn: "pos2", Message: "m2"},
				},
			},
			"b": {
				Diagnostics: []JSONDiagnostic{{Category: "c3", Posn: "pos3", Message: "m3"}},
			},
		},
		"pkg2": {
			"c": {
				Error: &jsonError{Err: "fail"},
			},
		},
	}
	got := jsonTreeToDiagnostics(in)
	want := []*bigquery.Diagnostic{
		{PackageID: "pkg1", AnalyzerName: "a", Category: "c1", Position: "pos1", Message: "m1"},
		{PackageID: "pkg1", AnalyzerName: "a", Category: "c2", Position: "pos2", Message: "m2"},
		{PackageID: "pkg1", AnalyzerName: "b", Category: "c3", Position: "pos3", Message: "m3"},
		{PackageID: "pkg2", AnalyzerName: "c", Error: "fail"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got)\n%s", diff)
	}

}
