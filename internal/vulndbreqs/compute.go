// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vulndbreqs supports recording the daily count of requests to the
// Vulnerability Database.
package vulndbreqs

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/logging/logadmin"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/log"
	"google.golang.org/api/iterator"
)

var startDate = civil.Date{Year: 2023, Month: time.January, Day: 1}

// ComputeAndStore computes Vuln DB request counts from the last date we have
// data for, and writes them to BigQuery.
func ComputeAndStore(ctx context.Context, vulndbBucketProjectID string, client *bigquery.Client) error {
	rcs, err := ReadFromBigQuery(ctx, client)
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
			// compute excludes both the start and end dates.
			rcs, err := Compute(ctx, vulndbBucketProjectID, d.AddDays(-1), d.AddDays(1), 0)
			if err != nil {
				return err
			}
			if len(rcs) > 1 {
				return fmt.Errorf("got %d counts, wanted 0 or 1", len(rcs))
			}
			if len(rcs) == 0 {
				rcs = []*RequestCount{{Date: d, Count: 0}}
			}
			// Write the new request counts to Bigquery.
			log.Infof(ctx, "writing request count %d for %s", rcs[0].Count, rcs[0].Date)
			if err := writeToBigQuery(ctx, client, rcs); err != nil {
				return err
			}
		}
	}
	return nil
}

// Compute queries the vulndb load balancer logs for all
// vuln DB requests between the given dates, exclusive of both.
// It returns request counts for each date, sorted from newest to oldest.
// If limit is positive, it reads no more than limit entries from the log (for testing only).
func Compute(ctx context.Context, vulndbBucketProjectID string, fromDate, toDate civil.Date, limit int) ([]*RequestCount, error) {
	log.Infof(ctx, "computing request counts from %s to %s", fromDate, toDate)
	client, err := logadmin.NewClient(ctx, vulndbBucketProjectID)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	counts := map[civil.Date]int{}

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

		timestamp>=`+fromDate.AddDays(1).String()+`
		timestamp<`+toDate.String())
	// Count each log entry we see, bucketing by date.
	// The timestamps are in order from oldest to newest
	// (https://cloud.google.com/logging/docs/reference/v2/rpc/google.logging.v2#google.logging.v2.ListLogEntriesRequest).
	var logErr error
	n := 1
	for {
		entry, err := it.Next()
		if err != nil {
			if err != iterator.Done {
				logErr = err
			}
			break
		}
		counts[civil.DateOf(entry.Timestamp)]++
		n++
		if limit > 0 && n > limit {
			break
		}
	}

	// Convert the counts map to a slice of VulnDBRquestCounts.
	var rcs []*RequestCount
	dates := maps.Keys(counts)
	// Sort from newest to oldest.
	slices.SortFunc(dates, func(d1, d2 civil.Date) bool { return d1.After(d2) })
	// If we encountered an error, try to make partial progress by returning
	// at least one day's worth of data.
	if logErr != nil {
		if len(dates) > 1 {
			// The last date may have partial data, so drop it.
			dates = dates[:len(dates)-1]
			log.Warnf(ctx, "error when reading load balancer logs, partial progress: %v",
				logErr)
		} else {
			log.Errorf(ctx, logErr, "when reading load balancer logs, no progress")
			return nil, logErr
		}
	}
	for _, d := range dates {
		rcs = append(rcs, &RequestCount{Date: d, Count: counts[d]})
	}
	log.Infof(ctx, "computed %d request counts", len(rcs))
	return rcs, nil
}
