// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/storage"
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

var (
	testHMACKey = []byte{0}

	// These reflect the contents of testdata/logfile.json,
	// which is also stored in the "test" directory of the
	// vulndb logs bucket.
	testFileDates = map[civil.Date]int{
		civil.Date{Year: 2023, Month: 5, Day: 30}: 13,
	}
	testFileIPs = map[string]int{
		obfuscate("1.2.3.4", testHMACKey):    3,
		obfuscate("5.6.7.8", testHMACKey):    2,
		obfuscate("9.10.11.12", testHMACKey): 8,
	}
)

func TestReadJSONLogEntries(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "logfile.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gotDates := map[civil.Date]int{}
	gotIPs := map[string]int{}
	err = readJSONLogEntries(f, testHMACKey, func(e *logEntry) error {
		gotDates[civil.DateOf(e.Timestamp)]++
		gotIPs[e.HTTPRequest.RemoteIP]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(gotDates, testFileDates) {
		t.Errorf("dates:\ngot  %v\nwant %v", gotDates, testFileDates)
	}
	if !maps.Equal(gotIPs, testFileIPs) {
		t.Errorf("IPs:\ngot  %v\nwant %v", gotIPs, testFileIPs)
	}
}

func TestCountFiles(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	// Actual bucket containing logs data.
	bucketName := os.Getenv("GOOGLE_CLOUD_PROJECT") + bucketSuffix

	// Files manually copied to the bucket for testing.
	const testPrefix = "test"
	testDate := civil.Date{Year: 2023, Month: 5, Day: 30}
	const wantPrefix = "test/2023/05/30/"

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	bucket := client.Bucket(bucketName)

	t.Run("ObjectNamesForDate", func(t *testing.T) {
		const wantNFiles = 2
		got, err := objectNamesForDate(ctx, bucket, testPrefix, testDate)
		if err != nil {
			t.Fatal(err)
		}
		if g := len(got); g != wantNFiles {
			t.Errorf("got %d files, want %d", g, wantNFiles)
		}

		for _, g := range got {
			if !strings.HasPrefix(g, wantPrefix) || !strings.HasSuffix(g, ".json") {
				t.Errorf(`got %q, want "%sFILENAME.json"`, g, wantPrefix)
			}
		}
	})

	t.Run("CountLogsForObjects", func(t *testing.T) {
		// The two files with the testPrefix are both copies of testdata/logfile.json.
		objNames := []string{wantPrefix + "logfile1.json", wantPrefix + "logfile2.json"}
		gotDates, gotIPs, err := countLogsForObjects(ctx, bucket, objNames, testHMACKey)
		if err != nil {
			t.Fatal(err)
		}
		// There are two files, so data is doubled.
		wantDates := maps.Clone(testFileDates)
		for k, v := range wantDates {
			wantDates[k] = v * 2
		}
		wantIPs := maps.Clone(testFileIPs)
		for k, v := range wantIPs {
			wantIPs[k] = v * 2
		}
		if !maps.Equal(gotDates, wantDates) {
			t.Errorf("dates:\ngot  %v\nwant %v", gotDates, wantDates)
		}
		if !maps.Equal(gotIPs, wantIPs) {
			t.Errorf("IPs:\ngot  %v\nwant %v", gotIPs, wantIPs)
		}
	})
}
