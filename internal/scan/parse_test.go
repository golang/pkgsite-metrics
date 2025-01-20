// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"flag"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/version"
)

var useGCS = flag.Bool("gcs", false, "use GCS in tests")

func TestParseModuleURLPath(t *testing.T) {
	for _, test := range []struct {
		path string
		want ModuleURLPath
	}{
		{
			"/module/@v/v1.0.0",
			ModuleURLPath{Module: "module", Version: "v1.0.0"},
		},
		{
			"/module/@v/v1.0.0-abcdefgh/suffix",
			ModuleURLPath{
				Module:  "module",
				Version: "v1.0.0-abcdefgh",
				Suffix:  "suffix",
			},
		},
		{
			"/module@v1.2.3/a/b/c",
			ModuleURLPath{
				Module:  "module",
				Version: "v1.2.3",
				Suffix:  "a/b/c",
			},
		},
	} {
		got, err := ParseModuleURLPath(test.path)
		if err != nil {
			t.Fatal(err)
		}
		if g, w := got, test.want; !cmp.Equal(g, w) {
			t.Errorf("%s:\ngot  %+v\nwant %+v", test.path, g, w)
		}
	}
}

func TestModuleURLPathError(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "InvalidScanURL",
			path: "/",
			want: `invalid path "/": missing '@'`,
		},
		{
			name: "InvalidScanURLNoModule",
			path: "/@v/version",
			want: `invalid path "/@v/version": missing module`,
		},
		{
			name: "InvalidScanURLNoVersion",
			path: "/module/@v/",
			want: `invalid path "/module/@v/": missing version`,
		},
		{
			name: "NoVersion",
			path: "/module@",
			want: `invalid path "/module@": missing version`,
		},
		{
			name: "NoVersionSuffix",
			path: "/module@/suffix",
			want: `invalid path "/module@/suffix": missing version`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseModuleURLPath(test.path); err != nil {
				if got := err.Error(); !strings.HasSuffix(got, test.want) {
					t.Fatalf("\ngot  %s\nwant suffix %s", got, test.want)
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

func TestReadFileLines(t *testing.T) {
	// Effectively tested for local files by ParseCorpusFile.
	// So just test for GCS.
	// This doesn't work in CI so protecct it with a flag.
	if !*useGCS {
		t.Skip("need -gcs")
	}
	got, err := ReadFileLines("gs://go-ecosystem/test-modfile")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mod1 v1.2.3 5",
		"mod2 v1.0.0 10",
		"mod3/v2 v2.1.2 0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("\ngot  %v\nwant %v", got, want)
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
	got := FormatParams(params{Str: "foo bar", Int: 17, Bool: true})
	want := "str=foo+bar&int=17&bool=true"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
