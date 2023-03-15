// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/version"
	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/osv"
	"google.golang.org/api/iterator"
)

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
					FoundVersion: "v0.0.1",
					Path:         "example.com/repo/module",
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
					FoundVersion: "v1.0.0",
					Path:         "example.com/repo/module",
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
		wantVulns []*Vuln
	}{
		{
			name: "call one symbol but not all",
			vuln: vuln1,
			wantVulns: []*Vuln{
				{
					ID:          "GO-YYYY-1234",
					PackagePath: "example.com/repo/module/package",
					ModulePath:  "example.com/repo/module",
					Version:     "v0.0.1",
					Called:      true,
				},
			},
		},
		{
			name: "call no symbols",
			vuln: vuln2,
			wantVulns: []*Vuln{
				{
					ID:          "GO-YYYY-1234",
					PackagePath: "example.com/repo/module/package",
					ModulePath:  "example.com/repo/module",
					Version:     "v1.0.0",
					Called:      false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(ConvertGovulncheckOutput(tt.vuln), tt.wantVulns, cmpopts.EquateEmpty(), cmp.AllowUnexported(Vuln{})); diff != "" {
				t.Errorf("mismatch (-got, +want): %s", diff)
			}
		})
	}
}

func TestSchemaString(t *testing.T) {
	type nest struct {
		N []byte
		M float64
	}

	type s struct {
		A string
		B int
		C []bool
		D nest
	}
	const want = "A,req:STRING;B,req:INTEGER;C,rep:BOOLEAN;D,req:(N,req:BYTES;M,req:FLOAT)"
	schema, err := bigquery.InferSchema(s{})
	if err != nil {
		t.Fatal(err)
	}
	got := bigquery.SchemaString(schema)
	if got != want {
		t.Errorf("\ngot  %q\nwant %q", got, want)
	}
}

var integration = flag.Bool("integration", false, "test against actual service")

func TestIntegration(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	if !*integration {
		t.Skip("missing -integration")
	}
	ctx := context.Background()
	const projectID = "go-ecosystem"

	// Create a new dataset ID to avoid problems with re-using existing tables.
	dsID := fmt.Sprintf("test_%s", time.Now().Format("20060102T030405"))
	t.Logf("using dataset %s", dsID)
	client, err := bigquery.NewClientCreate(ctx, projectID, dsID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		must(client.Dataset().Delete(ctx))
	}()

	if _, err := client.CreateOrUpdateTable(ctx, TableName); err != nil {
		t.Fatal(err)
	}
	defer func() { must(client.Table(TableName).Delete(ctx)) }()

	tm := time.Date(2022, 7, 21, 0, 0, 0, 0, time.UTC)
	row := &Result{
		ModulePath:  "m",
		Version:     "v",
		SortVersion: "sv",
		ImportedBy:  10,
		WorkVersion: WorkVersion{
			GoVersion:          "go1.19.6",
			WorkerVersion:      "1",
			SchemaVersion:      "s",
			VulnVersion:        "2",
			VulnDBLastModified: tm,
		},
	}

	t.Run("upload", func(t *testing.T) {
		must(client.Upload(ctx, TableName, row))
		// Round, strip monotonic data and convert to UTC.
		// Discrepancies of a few microseconds have been seen, so round to seconds
		// just to be safe.
		row.CreatedAt = row.CreatedAt.Round(time.Second).UTC()
		gots, err := readTable[Result](ctx, client.Table(TableName), nil)
		if err != nil {
			t.Fatal(err)
		}
		if g, w := len(gots), 1; g != w {
			t.Fatalf("got %d, rows, wanted %d", g, w)
		}
		got := gots[0]
		got.CreatedAt = got.CreatedAt.Round(time.Second)
		if diff := cmp.Diff(row, got); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}
	})
	t.Run("work versions", func(t *testing.T) {
		wv, err := ReadWorkVersions(ctx, client)
		if err != nil {
			t.Fatal(err)
		}
		wgot := wv[[2]string{"m", "v"}]
		if wgot == nil {
			t.Fatal("got nil, wanted work version")
		}
		if want := &row.WorkVersion; !wgot.Equal(want) {
			t.Errorf("got %+v, want %+v", wgot, want)
		}

		if got := wv[[2]string{"m", "v2"}]; got != nil {
			t.Errorf("got %v; want nil", got)
		}
	})

	t.Run("latest", func(t *testing.T) {
		latestTableID := TableName + "-latest"
		bigquery.AddTable(latestTableID, bigquery.TableSchema(TableName))
		must(client.CreateTable(ctx, latestTableID))
		defer func() { must(client.Table(latestTableID).Delete(ctx)) }()

		var want []*Result
		// Module "a": same work version, should get the latest module version.
		a1 := &Result{
			ModulePath: "a",
			Version:    "v1.0.0",
			ScanMode:   "M1",
			WorkVersion: WorkVersion{
				WorkerVersion:      "1",
				SchemaVersion:      "s",
				VulnVersion:        "2",
				VulnDBLastModified: tm,
			},
		}
		a2 := *a1
		a2.Version = "v1.1.0"
		want = append(want, &a2)

		// Different scan mode: should get this one too.
		a3 := a2
		a3.ScanMode = "M2"
		want = append(want, &a3)

		// Module "b": same module version, should get the latest work version.
		b1 := &Result{
			ModulePath: "b",
			Version:    "v1.0.0",
			WorkVersion: WorkVersion{
				WorkerVersion:      "1",
				SchemaVersion:      "s",
				VulnVersion:        "2",
				VulnDBLastModified: tm,
			},
		}
		b2 := *b1
		b2.WorkerVersion = "0"
		want = append(want, b1)

		vrs := []*Result{
			a1, &a2, &a3,
			b1, &b2,
		}
		for _, vr := range vrs {
			vr.SortVersion = version.ForSorting(vr.Version)
		}
		must(bigquery.UploadMany(ctx, client, latestTableID, vrs, 20))

		got, err := fetchResults(ctx, client, latestTableID)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(got, func(i, j int) bool { return got[i].ModulePath < got[j].ModulePath })
		if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(Result{}, "CreatedAt")); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}

		// Test InsertVulncheckResults
		reportTableID := latestTableID + "-report"
		bigquery.AddTable(reportTableID, bigquery.TableSchema(TableName+"-report"))
		reportTable := client.Dataset().Table(reportTableID)
		// Table is created by InsertVulncheckResults.
		defer func() { must(reportTable.Delete(ctx)) }()

		if err := insertResults(ctx, client, reportTableID, got, civil.DateOf(time.Now()), false); err != nil {
			t.Fatal(err)
		}
		rgot, err := readTable[ReportResult](ctx, reportTable, func() *ReportResult {
			return &ReportResult{Result: &Result{}}
		})
		if err != nil {
			t.Fatal(err)
		}
		wantDate := civil.DateOf(time.Now())
		for _, r := range rgot {
			if r.ReportDate != wantDate {
				t.Errorf("got %s, want %s", r.ReportDate, wantDate)
			}
			if d := time.Minute; time.Since(r.InsertedAt) > d {
				t.Errorf("inserted at %s, more than %s ago", r.InsertedAt, d)
			}
			// Sanity check for Result.
			if r.ModulePath != "a" && r.ModulePath != "b" {
				t.Errorf("got %q, want 'a' or 'b'", r.ModulePath)
			}

		}

	})
}

func readTable[T any](ctx context.Context, table *bq.Table, newT func() *T) ([]*T, error) {
	var ts []*T
	if newT == nil {
		newT = func() *T { return new(T) }
	}
	iter := table.Read(ctx)
	for {
		tp := newT()
		err := iter.Next(tp)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		ts = append(ts, tp)
	}
	return ts, nil
}
