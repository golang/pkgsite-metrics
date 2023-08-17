// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildbinary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const (
	localTestData = "../testdata"
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
			dir:     filepath.Join(localTestData, "module"),
			want:    []string{"golang.org/vuln"},
			wantErr: false,
		},
		{
			name:    "multiple test",
			dir:     filepath.Join(localTestData, "multipleBinModule"),
			want:    []string{"example.com/test", "example.com/test/multipleBinModule", "example.com/test/p1"},
			wantErr: false,
		},
		{
			name:    "error test",
			dir:     "non-existing-module",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findBinaries(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("got error=%v, wantErr=%v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("mismatch (-want, +got):%s", diff)
			}
		})
	}
}

func TestRunBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that uses internet in short mode")
	}

	tests := []struct {
		name       string
		modulePath string
		importPath string
		want       string
		wantErr    bool
	}{
		{
			name:       "local test",
			modulePath: filepath.Join(localTestData, "module"),
			importPath: "golang.org/vuln",
			want:       filepath.Join(localTestData, "module", "bin1"),
		},
		{
			name:       "multiple binaries",
			modulePath: filepath.Join(localTestData, "multipleBinModule"),
			importPath: "example.com/test/multipleBinModule",
			want:       filepath.Join(localTestData, "multipleBinModule", "bin1"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := runBuild(tt.modulePath, tt.importPath, 1)
			defer os.Remove(got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("got error=%v; wantErr=%v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):%s", diff)
			}
			_, err = os.Stat(got)
			if err != nil && os.IsNotExist(err) {
				t.Errorf("did not produce the expected binary")
			}
		})
	}
}
