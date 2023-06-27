// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildbinary

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func less(a, b string) bool {
	return a < b
}

func TestFindBinaries(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    []string
		wantErr bool
	}{
		{
			name:    "local test",
			dir:     "../testdata/module",
			want:    []string{"golang.org/vuln"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findBinaries(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("findBinaries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("mismatch (-want, +got):%s", diff)
			}
		})
	}
}
