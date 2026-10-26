// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vulndbreqs supports recording the daily count of requests to the
// Vulnerability Database.
package vulndbreqs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/logging/logadmin"
	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

var (
	// First date for which we want log data.
	startDate = civil.Date{Year: 2023, Month: time.January, Day: 1}

	// First date for which the GCS logs bucket has a full day of data. (There
	// is a directory for the day before, but doesn't include a whole day's
	// data.)
	gcsStartDate = civil.Date{Year: 2023, Month: time.May, Day: 31}
)

// ComputeAndStore computes Vuln DB request counts from the last date we have
// data for, and writes them to BigQuery.
func ComputeAndStore(ctx context.Context, vulndbBucketProjectID string, client *bigquery.Client) error {
	rcs, err := ReadRequestCountsFromBigQuery(ctx, client)
	if err != nil {
		return err
	}
	have := map[civil.Date]bool{}
	for _, rc := range rcs {
		have[rc.Date] = true
	}
	today := civil.DateOf(time.Now())
	// Compute requests for every day that we don't have, up until yesterday.
	// Since today is not yet over, the request count for it will be short.
	// Compute one day at a time, so if it fails after a few days we at least make some progress.
	for d := startDate; d.Before(today); d = d.AddDays(1) {
		if !have[d] {
			if err := ComputeAndStoreDate(ctx, vulndbBucketProjectID, client, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// ComputeAndStoreDate computes the request counts for the given date and writes them to BigQuery.
// It does so even if there is already stored information for that date.
func ComputeAndStoreDate(ctx context.Context, vulndbBucketProjectID string, client *bigquery.Client, date civil.Date) error {
	count, err := Compute(ctx, vulndbBucketProjectID, date)
	if err != nil {
		return err
	}
	log.Infof(ctx, "writing request count %d for %s", count, date)
	return writeToBigQuery(ctx, client, []*RequestCount{{Date: date, Count: count}})
}

// Compute computes counts for all vuln DB requests on the given date.
func Compute(ctx context.Context, vulndbBucketProjectID string, date civil.Date) (int, error) {
	if date.Before(gcsStartDate) {
		return computeFromLogs(ctx, vulndbBucketProjectID, date, 0)
	}
	return computeFromStorage(ctx, date, 0)
}

// computeFromLogs queries the vulndb load balancer logs for all vuln DB
// requests on the given date. It returns request counts for the date.
// If limit is positive, it reads no more than limit entries from the log (for testing only).
func computeFromLogs(ctx context.Context, vulndbBucketProjectID string, date civil.Date, limit int) (int, error) {
	log.Infof(ctx, "computing request counts for %s from logs", date)
	client, err := logadmin.NewClient(ctx, vulndbBucketProjectID)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	it := newEntryIterator(ctx, client,
		// This filter has three sections, marked with blank lines. It is more
		// efficient to do as much filtering as possible in the logging API
		// query, rather than in code.
		//
		// The first section of the filter selects the log of interest and
		// filters on general properties like severity.
		//
		// The second section filters on URL. Its first line makes sure
		// we're looking at a vulnDB URL. The other lines filter out
		// URLs we don't care about.  We only want URLs that refer to
		// modules, but we can't write that directly; instead, we have to
		// exclude some URLs. (The syntax `-FIELD=VALUE` means "FIELD
		// does not equal VALUE; a colon instead of an `=` means substring.)
		//
		// The third section selects the time of interest, based on the argument
		// times. It formats the times as dates like "2022-08-10". We want
		// the filter to be exclusive on both ends, so we use "<" for the end date,
		// and add one day to the start date.
		`
		resource.type=http_load_balancer
		resource.labels.forwarding_rule_name=go-vulndb-lb-forwarding-rule
		resource.labels.url_map_name=go-vulndb-lb
		severity=INFO
		httpRequest.requestMethod=GET

		httpRequest.requestUrl:"https://vuln.go.dev/"
		-httpRequest.requestUrl="https://vuln.go.dev/"
		-httpRequest.requestUrl="https://vuln.go.dev/index.json"
		-httpRequest.requestUrl:"https://vuln.go.dev/ID/"

		timestamp>=`+date.String()+`
		timestamp<`+date.AddDays(1).String())
	// Count each log entry we see.
	// The timestamps are in order from oldest to newest
	// (https://cloud.google.com/logging/docs/reference/v2/rpc/google.logging.v2#google.logging.v2.ListLogEntriesRequest).
	var logErr error
	count := 0
	for {
		_, err := it.Next()
		if err != nil {
			if err != iterator.Done {
				logErr = err
			}
			break
		}
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	if logErr != nil {
		log.Errorf(ctx, logErr, "when reading load balancer logs, no progress")
		return 0, logErr
	}

	return count, nil
}

// computeFromStorage counts requests for the given date from the files in the
// vulndb logs bucket.
// If maxFiles is positive, only that many files are read (for testing).
func computeFromStorage(ctx context.Context, date civil.Date, maxFiles int) (_ int, err error) {
	defer derrors.Wrap(&err, "computeFromStorage(%s)", date)

	log.Infof(ctx, "computing request counts for %s from storage bucket", date)
	client, err := storage.NewClient(ctx)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	bucketName := os.Getenv("GOOGLE_CLOUD_PROJECT") + bucketSuffix
	bucket := client.Bucket(bucketName)
	names, err := objectNamesForDate(ctx, bucket, logPrefix, date)
	if err != nil {
		return 0, err
	}
	if maxFiles > 0 && len(names) > maxFiles {
		names = names[:maxFiles]
	}

	byDate, err := countLogsForObjects(ctx, bucket, names)
	if err != nil {
		return 0, err
	}
	if len(byDate) != 1 {
		return 0, fmt.Errorf("got %d dates, want 1", len(byDate))
	}
	count, present := byDate[date]
	if !present {
		return 0, fmt.Errorf("no data for %s", date)
	}
	return count, nil
}

// countLogsForObjects reads the JSON log files given by objNames from the bucket
// and sums their entries by date.
func countLogsForObjects(ctx context.Context, bucket *storage.BucketHandle, objNames []string) (
	byDate map[civil.Date]int, err error) {

	if len(objNames) == 0 {
		return nil, nil
	}
	defer derrors.Wrap(&err, "countLogsForObjects(%q, ...[%d in total])", objNames[0], len(objNames))

	var mu sync.Mutex // Guards below.
	byRawDate := map[string]int{}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(64)
	for _, name := range objNames {
		name := name
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return nil // context cancelled, likely another routine erred
			default:
				r, err := bucket.Object(name).NewReader(ctx)
				if err != nil {
					return err
				}
				defer r.Close()

				localByRawDate := map[string]int{}
				err = readJSONLogEntries(name, r, func(e *logEntry) error {
					if len(e.Timestamp) < len("2006-01-02") {
						return errors.New("invalid timestamp")
					}
					localByRawDate[e.Timestamp[:len("2006-01-02")]]++
					return nil
				})
				if err != nil {
					return err
				}

				// Obtain the lock and update global byRawDate.
				mu.Lock()
				for d, c := range localByRawDate {
					byRawDate[d] += c
				}
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Convert map keyed with raw date to map keyed with civil.Date.
	byDate = make(map[civil.Date]int, len(byRawDate))
	for rawDate, count := range byRawDate {
		d, err := civil.ParseDate(rawDate)
		if err != nil {
			return nil, err
		}
		byDate[d] += count
	}
	return byDate, nil
}

// Suffix to append to project name to get the name of the logs bucket.
const bucketSuffix = "-vulndb-logs"

// Start of object names for vulndb request logs.
const logPrefix = "requests"

// objectNamesForDate returns the names of all objects in the bucket
// corresponding to the logPrefix and date.
// It assumes that the bucket is organized like a Cloud Logging storage sink for
// vulndb requests, with all files for a date in the directory
// logPrefix/YYYY/MM/DD.
func objectNamesForDate(ctx context.Context, bucket *storage.BucketHandle, logPrefix string, date civil.Date) (names []string, err error) {
	defer derrors.Wrap(&err, "objectNamesForDate(%q, %s)", logPrefix, date)

	q := &storage.Query{Prefix: fmt.Sprintf("%s/%04d/%02d/%02d/", logPrefix, date.Year, date.Month, date.Day)}
	q.SetAttrSelection([]string{"Name"}) // Retrieve only the name of the JSON file.
	iter := bucket.Objects(ctx, q)
	for {
		attrs, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		names = append(names, attrs.Name)
	}
	return names, nil
}

type logEntry struct {
	Timestamp string `json:"timestamp"`
}

var (
	timestampKey = []byte(`"timestamp":"`)
	quoteByte    = []byte(`"`)
)

// readJSONLogEntries reads the contents of r, which is named name and must consist of a sequence
// of JSON objects each of which has the fields of a logEntry, one per line.
// For each entry, it calls fn on the entry.
func readJSONLogEntries(name string, r io.Reader, fn func(e *logEntry) error) (err error) {
	defer derrors.Wrap(&err, "readJSONLogEntries(%s)", name)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var e logEntry
		_, tsRest, ok := bytes.Cut(line, timestampKey)
		if !ok {
			return errors.New("missing timestamp")
		}
		ts, _, ok := bytes.Cut(tsRest, quoteByte)
		if !ok {
			return errors.New("unterminated timestamp")
		}
		e.Timestamp = string(ts)

		if err := fn(&e); err != nil {
			return err
		}
	}
	return scanner.Err()
}
