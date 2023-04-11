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
	"github.com/google/go-cmp/cmp"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestCompute(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	projID := os.Getenv("GO_ECOSYSTEM_VULNDB_BUCKET_PROJECT")
	if projID == "" {
		t.Skip("GO_ECOSYSTEM_VULNDB_BUCKET_PROJECT not defined")
	}
	// Compute yesterday's counts, up to 10 log entries.
	// Assume there are more than 10 requests a day.
	yesterday := civil.DateOf(time.Now()).AddDays(-1)
	const n = 10
	igot, err := Compute(context.Background(), projID, yesterday, yesterday, n, []byte("fake-hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	got := sumRequestCounts(igot)
	want := []*RequestCount{{
		Date:  yesterday,
		Count: 10,
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
