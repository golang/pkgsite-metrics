// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
	got := JSONTreeToDiagnostics(in)
	want := []*Diagnostic{
		{PackageID: "pkg1", AnalyzerName: "a", Category: "c1", Position: "pos1", Message: "m1"},
		{PackageID: "pkg1", AnalyzerName: "a", Category: "c2", Position: "pos2", Message: "m2"},
		{PackageID: "pkg1", AnalyzerName: "b", Category: "c3", Position: "pos3", Message: "m3"},
		{PackageID: "pkg2", AnalyzerName: "c", Error: "fail"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got)\n%s", diff)
	}
}
