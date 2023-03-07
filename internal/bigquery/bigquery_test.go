// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

import (
	"context"
	"flag"
	"fmt"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/exp/slices"
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

	t.Run("request counts", func(t *testing.T) {
		date := func(y, m, d int) civil.Date {
			return civil.Date{Year: y, Month: time.Month(m), Day: d}
		}

		must(client.CreateTable(ctx, VulnDBRequestTableName))
		defer client.Table(VulnDBRequestTableName).Delete(ctx)
		counts := []*VulnDBRequestCount{
			{Date: date(2022, 10, 1), Count: 1},
			{Date: date(2022, 10, 3), Count: 3},
			{Date: date(2022, 10, 4), Count: 4},
		}
		for _, row := range counts {
			must(client.Upload(ctx, VulnDBRequestTableName, row))
		}
		// Insert duplicates with a later time; we expect to get these, not the originals.
		time.Sleep(50 * time.Millisecond)
		for _, row := range counts {
			row.Count++
			must(client.Upload(ctx, VulnDBRequestTableName, row))
		}

		got, err := readVulnDBRequestCounts(ctx, client)
		if err != nil {
			t.Fatal(err)
		}
		want := slices.Clone(counts)
		slices.SortFunc(want, func(c1, c2 *VulnDBRequestCount) bool { return c1.Date.After(c2.Date) })
		if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(VulnDBRequestCount{}, "InsertedAt")); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}
	})

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
