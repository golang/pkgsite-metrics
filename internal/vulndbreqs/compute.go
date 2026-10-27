// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vulndbreqs supports recording the daily count of requests to the
// Vulnerability Database.
package vulndbreqs

import (
	"context"
	"fmt"
	"os"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"cloud.google.com/go/logging/logadmin"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
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
	return computeFromStorage(ctx, logPrefix, date)
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

// computeFromStorage counts requests for the given date from the JSON log files
// in the vulndb logs bucket under logPrefix/YYYY/MM/DD/.
//
// The counting is done with a BigQuery query over a temporary external table
// backed by the files, so no file contents are transferred to this process.
// See https://cloud.google.com/bigquery/docs/external-data-sources.
func computeFromStorage(ctx context.Context, logPrefix string, date civil.Date) (_ int, err error) {
	defer derrors.Wrap(&err, "computeFromStorage(%q, %s)", logPrefix, date)

	log.Infof(ctx, "computing request counts for %s from storage bucket", date)
	projID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	client, err := bq.NewClient(ctx, projID)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	uri := fmt.Sprintf("gs://%s%s/%s/%04d/%02d/%02d/*", projID, bucketSuffix, logPrefix, date.Year, date.Month, date.Day)

	// Every log entry must have a valid timestamp: an invalid timestamp fails
	// CAST in BigQuery, and a missing (NULL) timestamp fails iter.Next below
	// when decoding into civil.Date.
	q := client.Query(`
		SELECT CAST(SUBSTR(timestamp, 1, 10) AS DATE) AS date, COUNT(*) AS count
		FROM temp_logs
		GROUP BY date
	`)
	q.TableDefinitions = map[string]bq.ExternalData{
		"temp_logs": &bq.ExternalDataConfig{
			SourceFormat:        bq.JSON,
			SourceURIs:          []string{uri},
			IgnoreUnknownValues: true,
			Schema: bq.Schema{
				{Name: "timestamp", Type: bq.StringFieldType},
			},
		},
	}

	iter, err := q.Read(ctx)
	if err != nil {
		return 0, err
	}
	byDate := make(map[civil.Date]int)
	for {
		var r struct {
			Date  civil.Date `bigquery:"date"`
			Count int        `bigquery:"count"`
		}
		err := iter.Next(&r)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return 0, err
		}
		byDate[r.Date] += r.Count
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

// Suffix to append to project name to get the name of the logs bucket.
const bucketSuffix = "-vulndb-logs"

// Start of object names for vulndb request logs.
const logPrefix = "requests"
