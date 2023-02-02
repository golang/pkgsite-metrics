// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/version"
)

func TestParseScanRequest(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		want ScanRequest
	}{
		{
			name: "ValidScanURL",
			url:  "https://worker.com/scan/module/@v/v1.0.0?importedby=50",
			want: ScanRequest{
				Module:     "module",
				Version:    "v1.0.0",
				ImportedBy: 50,
				Mode:       "",
			},
		},
		{
			name: "ValidImportsOnlyScanURL",
			url:  "https://worker.com/scan/module/@v/v1.0.0-abcdefgh?importedby=100&mode=mode1",
			want: ScanRequest{
				Module:     "module",
				Version:    "v1.0.0-abcdefgh",
				ImportedBy: 100,
				Mode:       "mode1",
			},
		},
		{
			name: "Module@Version",
			url:  "https://worker.com/scan/module@v1.2.3?importedby=1",
			want: ScanRequest{
				Module:     "module",
				Version:    "v1.2.3",
				ImportedBy: 1,
				Mode:       "",
			},
		},
		{
			name: "Module@Version suffix",
			url:  "https://worker.com/scan/module@v1.2.3/path/to/dir?importedby=1",
			want: ScanRequest{
				Module:     "module",
				Version:    "v1.2.3",
				Suffix:     "path/to/dir",
				ImportedBy: 1,
				Mode:       "",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.Parse(test.url)
			if err != nil {
				t.Errorf("url.Parse(%q): %v", test.url, err)
			}
			r := &http.Request{URL: u}
			got, err := ParseScanRequest(r, "/scan")
			if err != nil {
				t.Fatal(err)
			}
			if g, w := *got, test.want; g != w {
				t.Errorf("\ngot  %+v\nwant %+v", g, w)
			}
		})
	}
}

func TestParseScanRequestError(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		want string
	}{
		{
			name: "InvalidScanURL",
			url:  "/",
			want: `invalid path "/": missing '@'`,
		},
		{
			name: "InvalidScanURLNoModule",
			url:  "/@v/version",
			want: `invalid path "/@v/version": missing module`,
		},
		{
			name: "InvalidScanURLNoVersion",
			url:  "/module/@v/",
			want: `invalid path "/module/@v/": missing version`,
		},
		{
			name: "NoVersion",
			url:  "/module@",
			want: `invalid path "/module@": missing version`,
		},
		{
			name: "NoVersionSuffix",
			url:  "/module@/suffix",
			want: `invalid path "/module@/suffix": missing version`,
		},
		{
			name: "MissingImportedBy",
			url:  "/module/@v/v1.0.0",
			want: `missing query param "importedby"`,
		},
		{
			name: "BadImportedBy",
			url:  "/module@v1?importedby=1a",
			want: `want integer for "importedby" query param, got "1a"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.Parse(test.url)
			if err != nil {
				t.Errorf("url.Parse(%q): %v", test.url, err)
			}
			r := &http.Request{URL: u}
			if _, err := ParseScanRequest(r, "/scan"); err != nil {
				if got := err.Error(); got != test.want {
					t.Fatalf("\ngot  %s\nwant %s", got, test.want)
				}
			} else {
				t.Fatalf("error = nil; want = (%v)", test.want)
			}
		})
	}
}

func TestParseCorpusFile(t *testing.T) {
	const file = "testdata/modules.txt"
	got, err := ParseCorpusFile(file, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []ModuleSpec{
		{"m1", "v1.0.0", 18},
		{"m2", "v2.3.4", 5},
		{"m3", version.Latest, 1},
	}

	if !cmp.Equal(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}

	got, err = ParseCorpusFile(file, 10)
	if err != nil {
		t.Fatal(err)
	}
	want = want[:1]
	if !cmp.Equal(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}
