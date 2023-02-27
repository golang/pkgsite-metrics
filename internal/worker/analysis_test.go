// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
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
