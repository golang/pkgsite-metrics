// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"fmt"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/osv"
	test "golang.org/x/pkgsite-metrics/internal/testing"
	"golang.org/x/vuln/exp/govulncheck"
	oldOsv "golang.org/x/vuln/osv"
	"google.golang.org/api/iterator"
)

func TestConvertGovulncheckOutput(t *testing.T) {
	var (
		newOsvEntry = &osv.Entry{
			ID: "GO-YYYY-1234",
			Affected: []osv.Affected{
				{
					Module: osv.Module{
						Path:      "example.com/repo/module",
						Ecosystem: "Go",
					},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{
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
		osvEntry = &oldOsv.Entry{
			ID: newOsvEntry.ID,
			Affected: []oldOsv.Affected{
				{
					Package: oldOsv.Package{
						Name:      "example.com/repo/module",
						Ecosystem: "Go",
					},
					EcosystemSpecific: oldOsv.EcosystemSpecific{
						Imports: []oldOsv.EcosystemSpecificImport{
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

func TestIntegration(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
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
			VulnDBLastModified: tm,
		},
		ErrorCategory: "SOME ERROR",
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
		wss, err := ReadWorkStates(ctx, client)
		if err != nil {
			t.Fatal(err)
		}
		wsgot := wss[[2]string{"m", "v"}]
		if wsgot == nil {
			t.Fatal("got nil, wanted work state")
		}
		wgot := wsgot.WorkVersion
		if wgot == nil {
			t.Fatal("got nil, wanted work version")
		}
		if want := &row.WorkVersion; !wgot.Equal(want) {
			t.Errorf("got %+v, want %+v", wgot, want)
		}
		egot := wsgot.ErrorCategory
		if want := row.ErrorCategory; want != egot {
			t.Errorf("got %+v, want %+v", egot, want)
		}
		if got := wss[[2]string{"m", "v2"}]; got != nil {
			t.Errorf("got %v; want nil", got)
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
