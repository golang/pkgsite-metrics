// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"slices"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestBigQuery(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	const projectID = "go-ecosystem"

	client, err := bigquery.NewClientForTesting(ctx, projectID, "bigquery")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	date := func(y, m, d int) civil.Date {
		return civil.Date{Year: y, Month: time.Month(m), Day: d}
	}

	counts := []*IPRequestCount{
		{Date: date(2022, 10, 1), IP: "A", Count: 1},
		{Date: date(2022, 10, 3), IP: "B", Count: 3},
		{Date: date(2022, 10, 4), IP: "C", Count: 4},
	}
	must(writeToBigQuery(ctx, client, sumRequestCounts(counts), counts))
	// Insert duplicates with a later time; we expect to get these, not the originals.
	time.Sleep(50 * time.Millisecond)
	for _, row := range counts {
		row.Count++
	}
	want := sumRequestCounts(counts)
	must(writeToBigQuery(ctx, client, want, counts))

	got, err := ReadRequestCountsFromBigQuery(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(want, func(c1, c2 *RequestCount) int { return -1 * compareDate(c1.Date, c2.Date) })
	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(RequestCount{}, "CreatedAt")); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

// compareDate compares d1 and d2. If d1 is before d2, it returns -1;
// if d1 is after d2, it returns +1; otherwise it returns 0.
//
// TODO(go.dev/issue/74596): Delete and replace with
// https://pkg.go.dev/cloud.google.com/go/civil#Date.Compare
// after updating that module to v0.114.0 or higher.
func compareDate(d1, d2 civil.Date) int {
	if d1.Before(d2) {
		return -1
	} else if d1.After(d2) {
		return +1
	}
	return 0
}
