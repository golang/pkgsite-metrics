// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndb

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/osv"
)

func TestConvert(t *testing.T) {
	oe := &osv.Entry{
		ID: "a",
		Affected: []osv.Affected{
			{Package: osv.Package{Name: "example.mod/a"}, Ranges: []osv.AffectsRange{{Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "0.9.0"}}}}},
			{Package: osv.Package{Name: "a.example.mod/a"}, Ranges: []osv.AffectsRange{{Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}},
		}}
	want := &Entry{
		ID: "a",
		Modules: []Module{
			{
				Path:   "example.mod/a",
				Ranges: []Range{{Introduced: "0"}, {Fixed: "0.9.0"}},
			},
			{
				Path:   "a.example.mod/a",
				Ranges: []Range{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}},
			},
		},
	}
	got := Convert(oe)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}
