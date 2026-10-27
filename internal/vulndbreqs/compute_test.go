// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestComputeFromLogs(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	projID := os.Getenv("GO_ECOSYSTEM_VULNDB_BUCKET_PROJECT")
	if projID == "" {
		t.Skip("GO_ECOSYSTEM_VULNDB_BUCKET_PROJECT not defined")
	}
	// Compute yesterday's counts, up to 10 log entries.
	// Assume there are more than 10 requests a day.
	yesterday := civil.DateOf(time.Now()).AddDays(-1)
	const n = 10
	got, err := computeFromLogs(context.Background(), projID, yesterday, n)
	if err != nil {
		t.Fatal(err)
	}
	const want = 10
	if got != want {
		t.Errorf("got %d, want %d", got, want)
	}
}

func TestComputeFromStorage(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	// The "test/2023/05/30/" directory in the vulndb logs bucket contains two
	// copies of testdata/logfile.json (13 entries each).
	testDate := civil.Date{Year: 2023, Month: 5, Day: 30}
	got, err := computeFromStorage(context.Background(), "test", testDate)
	if err != nil {
		t.Fatal(err)
	}
	const want = 13 * 2
	if got != want {
		t.Errorf("got %d, want %d", got, want)
	}

	// A date with no files should return an error.
	if _, err := computeFromStorage(context.Background(), "test", testDate.AddDays(-1)); err == nil {
		t.Error("got nil, want error for missing date")
	}
}
