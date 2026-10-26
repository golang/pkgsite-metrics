// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/storage"
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

	// Compute one day's counts, reading only 1 file.
	// The file is always the same.
	got, err := computeFromStorage(context.Background(), testDate, 1)
	if err != nil {
		t.Fatal(err)
	}
	const want = 175
	if got != want {
		t.Errorf("got %d, want %d", got, want)
	}
}

var (
	testDate = civil.Date{Year: 2023, Month: 5, Day: 30}

	// These reflect the contents of testdata/logfile.json,
	// which is also stored in the "test" directory of the
	// vulndb logs bucket.
	testFileDates = map[civil.Date]int{testDate: 13}
)

func TestReadJSONLogEntries(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "logfile.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gotDates := map[civil.Date]int{}
	err = readJSONLogEntries("logfile.json", f, func(e *logEntry) error {
		d, err := civil.ParseDate(e.Timestamp[:len("2006-01-02")])
		if err != nil {
			return err
		}
		gotDates[d]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(gotDates, testFileDates) {
		t.Errorf("dates:\ngot  %v\nwant %v", gotDates, testFileDates)
	}
}

func TestCountFiles(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	// Actual bucket containing logs data.
	bucketName := os.Getenv("GOOGLE_CLOUD_PROJECT") + bucketSuffix

	// Files manually copied to the bucket for testing.
	const testPrefix = "test"
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
		gotDates, err := countLogsForObjects(ctx, bucket, objNames)
		if err != nil {
			t.Fatal(err)
		}
		// There are two files, so data is doubled.
		wantDates := maps.Clone(testFileDates)
		for k, v := range wantDates {
			wantDates[k] = v * 2
		}
		if !maps.Equal(gotDates, wantDates) {
			t.Errorf("dates:\ngot  %v\nwant %v", gotDates, wantDates)
		}
	})
}
