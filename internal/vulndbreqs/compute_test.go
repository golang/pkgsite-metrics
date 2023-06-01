// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/maps"
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
	igot, err := Compute(context.Background(), projID, yesterday, yesterday, n, []byte("this-is-a-fake-hmac-key"))
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

func TestReadJSONLogEntries(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "logfile.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gotDate := map[civil.Date]int{}
	gotIP := map[string]int{}
	hmacKey := []byte{0}
	err = readJSONLogEntries(f, hmacKey, func(e *logEntry) error {
		gotDate[civil.DateOf(e.Timestamp)]++
		gotIP[e.HTTPRequest.RemoteIP]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantDate := map[civil.Date]int{
		civil.Date{Year: 2023, Month: 5, Day: 30}: 13,
	}
	wantIP := map[string]int{
		obfuscate("1.2.3.4", hmacKey):    3,
		obfuscate("5.6.7.8", hmacKey):    2,
		obfuscate("9.10.11.12", hmacKey): 8,
	}
	if !maps.Equal(gotDate, wantDate) {
		t.Errorf("dates:\ngot  %v\nwant %v", gotDate, wantDate)
	}
	if !maps.Equal(gotIP, wantIP) {
		t.Errorf("IPs:\ngot  %v\nwant %v", gotIP, wantIP)
	}
}
