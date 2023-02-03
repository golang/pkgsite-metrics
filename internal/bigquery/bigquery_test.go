// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

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
	"golang.org/x/pkgsite-metrics/internal/version"
	"google.golang.org/api/iterator"
)

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
	client, err := NewClientCreate(ctx, projectID, dsID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		must(client.dataset.Delete(ctx))
	}()

	if _, err := client.CreateOrUpdateTable(ctx, VulncheckTableName); err != nil {
		t.Fatal(err)
	}
	defer func() { must(client.Table(VulncheckTableName).Delete(ctx)) }()

	tm := time.Date(2022, 7, 21, 0, 0, 0, 0, time.UTC)
	row := &VulnResult{
		ModulePath:  "m",
		Version:     "v",
		SortVersion: "sv",
		ImportedBy:  10,
		VulncheckWorkVersion: VulncheckWorkVersion{
			WorkerVersion:      "1",
			SchemaVersion:      "s",
			VulnVersion:        "2",
			VulnDBLastModified: tm,
		},
	}

	t.Run("upload", func(t *testing.T) {
		must(client.Upload(ctx, VulncheckTableName, row))
		// Round, strip monotonic data and convert to UTC.
		// Discrepancies of a few microseconds have been seen, so round to seconds
		// just to be safe.
		row.CreatedAt = row.CreatedAt.Round(time.Second).UTC()
		gots, err := readTable[VulnResult](ctx, client.Table(VulncheckTableName), nil)
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
		wv, err := ReadVulncheckWorkVersions(ctx, client)
		if err != nil {
			t.Fatal(err)
		}
		wgot := wv[[2]string{"m", "v"}]
		if wgot == nil {
			t.Fatal("got nil, wanted work version")
		}
		if want := &row.VulncheckWorkVersion; !wgot.Equal(want) {
			t.Errorf("got %+v, want %+v", wgot, want)
		}

		if got := wv[[2]string{"m", "v2"}]; got != nil {
			t.Errorf("got %v; want nil", got)
		}
	})

	t.Run("latest", func(t *testing.T) {
		latestTableID := VulncheckTableName + "-latest"
		addTable(latestTableID, tableSchema(VulncheckTableName))
		must(client.CreateTable(ctx, latestTableID))
		defer func() { must(client.Table(latestTableID).Delete(ctx)) }()

		var want []*VulnResult
		// Module "a": same work version, should get the latest module version.
		a1 := &VulnResult{
			ModulePath: "a",
			Version:    "v1.0.0",
			ScanMode:   "M1",
			VulncheckWorkVersion: VulncheckWorkVersion{
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
		b1 := &VulnResult{
			ModulePath: "b",
			Version:    "v1.0.0",
			VulncheckWorkVersion: VulncheckWorkVersion{
				WorkerVersion:      "1",
				SchemaVersion:      "s",
				VulnVersion:        "2",
				VulnDBLastModified: tm,
			},
		}
		b2 := *b1
		b2.WorkerVersion = "0"
		want = append(want, b1)

		vrs := []*VulnResult{
			a1, &a2, &a3,
			b1, &b2,
		}
		for _, vr := range vrs {
			vr.SortVersion = version.ForSorting(vr.Version)
		}
		must(UploadMany(ctx, client, latestTableID, vrs, 20))

		got, err := fetchVulncheckResults(ctx, client, latestTableID)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(got, func(i, j int) bool { return got[i].ModulePath < got[j].ModulePath })
		if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(VulnResult{}, "CreatedAt")); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}

		// Test InsertVulncheckResults
		reportTableID := latestTableID + "-report"
		addTable(reportTableID, tableSchema(VulncheckTableName+"-report"))
		reportTable := client.dataset.Table(reportTableID)
		// Table is created by InsertVulncheckResults.
		defer func() { must(reportTable.Delete(ctx)) }()

		if err := insertVulncheckResults(ctx, client, reportTableID, got, civil.DateOf(time.Now()), false); err != nil {
			t.Fatal(err)
		}
		rgot, err := readTable[ReportVulnResult](ctx, reportTable, func() *ReportVulnResult {
			return &ReportVulnResult{VulnResult: &VulnResult{}}
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
			// Sanity check for VulnResult.
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

func TestIsNotFoundError(t *testing.T) {
	if !*integration {
		t.Skip("missing -integration")
	}
	client, err := bq.NewClient(context.Background(), "go-ecosystem")
	if err != nil {
		t.Fatal(err)
	}
	dataset := client.Dataset("nope")
	_, err = dataset.Metadata(context.Background())
	if !isNotFoundError(err) {
		t.Errorf("got false, want true for %v", err)
	}
}
