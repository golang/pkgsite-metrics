// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

var integration = flag.Bool("integration", false, "test against actual service")

func TestAsScanError(t *testing.T) {
	check := func(err error, want bool) {
		if got := errors.As(err, new(scanError)); got != want {
			t.Errorf("%T: got %t, want %t", err, got, want)
		}
	}
	check(io.EOF, false)
	check(scanError{io.EOF}, true)
}

func TestRunScanModule(t *testing.T) {
	t.Skip("breaks on trybots")

	ctx := context.Background()
	cfg, err := config.Init(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dbClient, err := vulnc.NewClient([]string{cfg.VulnDBURL}, vulnc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	proxyClient, err := proxy.New(cfg.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("source", func(t *testing.T) {
		s := &scanner{proxyClient: proxyClient, dbClient: dbClient, insecure: true}
		stats := &vulncheckStats{}
		vulns, err := s.runScanModule(ctx,
			"golang.org/x/exp/event", "v0.0.0-20220929112958-4a82f8963a65",
			"", ModeVTAStacks, stats)
		if err != nil {
			t.Fatal(err)
		}
		wantID := "GO-2022-0493"
		found := false
		for _, v := range vulns {
			if v.ID == wantID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("want %s, did not find it in %d vulns", wantID, len(vulns))
		}
		if got := stats.scanMemory; got <= 0 {
			t.Errorf("scan memory not collected or negative: %v", got)
		}
		if got := stats.pkgsMemory; got <= 0 {
			t.Errorf("pkgs memory not collected or negative: %v", got)
		}
	})
	t.Run("memoryLimit", func(t *testing.T) {
		s := &scanner{proxyClient: proxyClient, dbClient: dbClient, insecure: true, goMemLimit: 2000}
		_, err := s.runScanModule(ctx, "golang.org/x/mod", "v0.5.1",
			"", ModeVTAStacks, &vulncheckStats{})
		if !errors.Is(err, derrors.ScanModuleMemoryLimitExceeded) {
			t.Errorf("got %v, want MemoryLimitExceeded", err)
		}
	})
	t.Run("binary", func(t *testing.T) {
		if !*integration { // needs GCS read permission, not available on kokoro
			t.Skip("missing -integration")
		}
		s := &scanner{proxyClient: proxyClient, dbClient: dbClient}
		gcsClient, err := storage.NewClient(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		s.gcsBucket = gcsClient.Bucket("go-ecosystem")
		stats := &vulncheckStats{}
		vulns, err := s.runScanModule(ctx, "golang.org/x/pkgsite", "v0.0.0-20221004150836-873fb37c2479", "cmd/worker", ModeBinary, stats)
		if err != nil {
			t.Fatal(err)
		}
		if g, w := len(vulns), 14; g != w {
			t.Errorf("got %d vulns, want %d", g, w)
		}
	})
	t.Run("govulncheck", func(t *testing.T) {
		s := &scanner{proxyClient: proxyClient, dbClient: dbClient, insecure: true}
		stats := &vulncheckStats{}
		vulns, err := s.runScanModule(ctx,
			"golang.org/x/exp/event", "v0.0.0-20220929112958-4a82f8963a65",
			"", ModeGovulncheck, stats)
		if err != nil {
			t.Fatal(err)
		}
		wantID := "GO-2022-0493"
		found := false
		for _, v := range vulns {
			if v.ID == wantID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("want %s, did not find it in %d vulns", wantID, len(vulns))
		}
		if got := stats.scanSeconds; got <= 0 {
			t.Errorf("scan time not collected or negative: %v", got)
		}
	})
}

func TestParseGoMemLimit(t *testing.T) {
	for _, test := range []struct {
		in   string
		want uint64
	}{
		{"", 0},
		{"foo", 0},
		{"23", 23},
		{"56Ki", 56 * 1024},
		{"3Mi", 3 * 1024 * 1024},
		{"8Gi", 8 * 1024 * 1024 * 1024},
	} {
		got := parseGoMemLimit(test.in)
		if got != test.want {
			t.Errorf("%q: got %d, want %d", test.in, got, test.want)
		}
	}
}

func TestUnmarshalVulncheckOutput(t *testing.T) {
	_, err := unmarshalVulncheckOutput([]byte(`{"Error": "bad"}`))
	if got, want := err.Error(), "bad"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	want := &vulncheck.Result{
		Modules: []*vulncheck.Module{{Path: "m", Version: "v1.2.3"}},
	}
	in, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalVulncheckOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestConvertGovulncheckOutput(t *testing.T) {
	var (
		osvEntry = &osv.Entry{
			ID: "GO-YYYY-1234",
			Affected: []osv.Affected{
				{
					Package: osv.Package{
						Name:      "example.com/repo/module",
						Ecosystem: "Go",
					},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{
							{
								Path: "example.com/repo/module/package",
								Symbols: []string{
									"Symbol",
									"Another",
								},
							},
						},
					},
				},
			},
		}

		vuln1 = &govulncheck.Vuln{
			OSV: osvEntry,
			Modules: []*govulncheck.Module{
				{
					Path: "example.com/repo/module",
					Packages: []*govulncheck.Package{
						{
							Path: "example.com/repo/module/package",
							CallStacks: []govulncheck.CallStack{
								{
									Symbol:  "Symbol",
									Summary: "example.go:1:1 xyz.func calls pkgPath.Symbol",
									Frames:  []*govulncheck.StackFrame{},
								},
							},
						},
					},
				},
			},
		}

		vuln2 = &govulncheck.Vuln{
			OSV: osvEntry,
			Modules: []*govulncheck.Module{
				{
					Path: "example.com/repo/module",
					Packages: []*govulncheck.Package{
						{
							Path: "example.com/repo/module/package",
						},
					},
				},
			},
		}
	)
	tests := []struct {
		name      string
		vuln      *govulncheck.Vuln
		wantVulns []*bigquery.Vuln
	}{
		{
			name: "Call One Symbol",
			vuln: vuln1,
			wantVulns: []*bigquery.Vuln{
				{
					ID:          "GO-YYYY-1234",
					Symbol:      "Symbol",
					PackagePath: "example.com/repo/module/package",
					ModulePath:  "example.com/repo/module",
					CallSink:    bigquery.NullInt(1),
					ImportSink:  bigquery.NullInt(1),
					RequireSink: bigquery.NullInt(1),
				},
				{
					ID:          "GO-YYYY-1234",
					Symbol:      "Another",
					PackagePath: "example.com/repo/module/package",
					ModulePath:  "example.com/repo/module",
					CallSink:    bigquery.NullInt(0),
					ImportSink:  bigquery.NullInt(1),
					RequireSink: bigquery.NullInt(1),
				},
			},
		},
		{
			name: "Call no symbols",
			vuln: vuln2,
			wantVulns: []*bigquery.Vuln{
				{
					ID:          "GO-YYYY-1234",
					PackagePath: "example.com/repo/module/package",
					ModulePath:  "example.com/repo/module",
					Symbol:      "Symbol",
					CallSink:    bigquery.NullInt(0),
					ImportSink:  bigquery.NullInt(1),
					RequireSink: bigquery.NullInt(1),
				},
				{
					ID:          "GO-YYYY-1234",
					PackagePath: "example.com/repo/module/package",
					ModulePath:  "example.com/repo/module",
					Symbol:      "Another",
					CallSink:    bigquery.NullInt(0),
					ImportSink:  bigquery.NullInt(1),
					RequireSink: bigquery.NullInt(1),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(convertGovulncheckOutput(tt.vuln), tt.wantVulns, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-got, +want): %s", diff)
			}
		})
	}
}
