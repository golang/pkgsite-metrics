// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/version"
)

func TestParseScanRequest(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		want Request
	}{
		{
			name: "ValidScanURL",
			url:  "https://worker.com/scan/module/@v/v1.0.0?importedby=50",
			want: Request{
				ModuleURLPath{Module: "module", Version: "v1.0.0"},
				RequestParams{ImportedBy: 50, Mode: ""},
			},
		},
		{
			name: "ValidImportsOnlyScanURL",
			url:  "https://worker.com/scan/module/@v/v1.0.0-abcdefgh?importedby=100&mode=mode1",
			want: Request{
				ModuleURLPath{Module: "module", Version: "v1.0.0-abcdefgh"},
				RequestParams{ImportedBy: 100, Mode: "mode1"},
			},
		},
		{
			name: "Module@Version",
			url:  "https://worker.com/scan/module@v1.2.3?importedby=1",
			want: Request{
				ModuleURLPath{Module: "module", Version: "v1.2.3"},
				RequestParams{ImportedBy: 1, Mode: ""},
			},
		},
		{
			name: "Module@Version suffix",
			url:  "https://worker.com/scan/module@v1.2.3/path/to/dir?importedby=1",
			want: Request{
				ModuleURLPath{Module: "module", Version: "v1.2.3", Suffix: "path/to/dir"},
				RequestParams{ImportedBy: 1, Mode: ""},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.Parse(test.url)
			if err != nil {
				t.Errorf("url.Parse(%q): %v", test.url, err)
			}
			r := &http.Request{URL: u}
			got, err := ParseRequest(r, "/scan")
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
			want: `missing or negative "importedby" query param`,
		},
		{
			name: "BadImportedBy",
			url:  "/module@v1?importedby=1a",
			want: `param importedby: strconv.Atoi: parsing "1a": invalid syntax`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.Parse(test.url)
			if err != nil {
				t.Errorf("url.Parse(%q): %v", test.url, err)
			}
			r := &http.Request{URL: u}
			if _, err := ParseRequest(r, "/scan"); err != nil {
				if got := err.Error(); !strings.Contains(got, test.want) {
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

type params struct {
	Str  string
	Int  int
	Bool bool
}

func TestParseParams(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		for _, test := range []struct {
			params string
			want   params
		}{
			{
				"str=foo&int=1&bool=true",
				params{Str: "foo", Int: 1, Bool: true},
			},
			{
				"", // all defaults
				params{Str: "d", Int: 17, Bool: false},
			},
			{
				"int=3&bool=t&str=", // empty string is same as default
				params{Str: "d", Int: 3, Bool: true},
			},
		} {
			r, err := http.NewRequest("GET", "https://path?"+test.params, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := params{Str: "d", Int: 17} // set defaults
			if err := ParseParams(r, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("%q: \ngot  %+v\nwant %+v", test.params, got, test.want)
			}
		}
	})
	t.Run("errors", func(t *testing.T) {
		for _, test := range []struct {
			arg         any
			params      string
			errContains string
		}{
			{3, "", "struct pointer"},
			{&params{}, "int=foo", "invalid syntax"},
			{&params{}, "bool=foo", "invalid syntax"},
			{&struct{ F float64 }{}, "f=1.1", "cannot parse kind"},
		} {
			r, err := http.NewRequest("GET", "https://path?"+test.params, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = ParseParams(r, test.arg)
			got := "<nil>"
			if err != nil {
				got = err.Error()
			}
			if !strings.Contains(got, test.errContains) {
				t.Errorf("%v, %q: got %q, want string containing %q", test.arg, test.params, got, test.errContains)
			}
		}
	})
}

func TestFormatParams(t *testing.T) {
	got := FormatParams(params{Str: "foo", Int: 17, Bool: true})
	want := "str=foo&int=17&bool=true"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
