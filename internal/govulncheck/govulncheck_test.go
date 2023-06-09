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
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	test "golang.org/x/pkgsite-metrics/internal/testing"
	"google.golang.org/api/iterator"
)

func TestConvertGovulncheckFinding(t *testing.T) {
	var (
		osvID = "GO-YYYY-XXXX"
		vuln1 = &govulncheckapi.Finding{
			OSV: osvID,
			Trace: []*govulncheckapi.Frame{
				{
					Module:   "example.com/repo/module",
					Version:  "v0.0.1",
					Package:  "example.com/repo/module/package",
					Function: "func",
					Position: &govulncheckapi.Position{},
				},
			},
		}

		vuln2 = &govulncheckapi.Finding{
			OSV:          osvID,
			FixedVersion: "",
			Trace: []*govulncheckapi.Frame{
				{
					Module:   "example.com/repo/module",
					Version:  "v1.0.0",
					Package:  "example.com/repo/module/package",
					Position: nil,
				},
			},
		}
	)
	tests := []struct {
		name     string
		vuln     *govulncheckapi.Finding
		wantVuln *Vuln
	}{
		{
			name: "called",
			vuln: vuln1,
			wantVuln: &Vuln{
				ID:          "GO-YYYY-XXXX",
				PackagePath: "example.com/repo/module/package",
				ModulePath:  "example.com/repo/module",
				Version:     "v0.0.1",
				Called:      true,
			},
		},
		{
			name: "Not called",
			vuln: vuln2,
			wantVuln: &Vuln{
				ID:          "GO-YYYY-XXXX",
				PackagePath: "example.com/repo/module/package",
				ModulePath:  "example.com/repo/module",
				Version:     "v1.0.0",
				Called:      false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(ConvertGovulncheckFinding(tt.vuln), tt.wantVuln, cmp.AllowUnexported(Vuln{})); diff != "" {
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
		ws, err := ReadWorkState(ctx, client, "m", "v")
		if err != nil {
			t.Fatal(err)
		}
		if ws == nil {
			t.Fatal("got nil, wanted work state")
		}
		wgot := ws.WorkVersion
		if wgot == nil {
			t.Fatal("got nil, wanted work version")
		}
		if want := &row.WorkVersion; !wgot.Equal(want) {
			t.Errorf("got %+v, want %+v", wgot, want)
		}
		egot := ws.ErrorCategory
		if want := row.ErrorCategory; want != egot {
			t.Errorf("got %+v, want %+v", egot, want)
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
