// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/civil"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
)

const (
	// Vuln DB requests live in their own dataset that doesn't vary.
	DatasetName             = "vulndb"
	RequestCountTableName   = "requests"
	IPRequestCountTableName = "ip-requests"
)

func init() {
	s, err := bigquery.InferSchema(RequestCount{})
	if err != nil {
		panic(err)
	}
	bigquery.AddTable(RequestCountTableName, s)
	s, err = bigquery.InferSchema(IPRequestCount{})
	if err != nil {
		panic(err)
	}
	bigquery.AddTable(IPRequestCountTableName, s)
}

// RequestCount holds the number of requests made on a date.
type RequestCount struct {
	CreatedAt time.Time  `bigquery:"created_at"`
	Date      civil.Date `bigquery:"date"` // year-month-day without a timezone
	Count     int        `bigquery:"count"`
}

// SetUploadTime is used by Client.Upload.
func (r *RequestCount) SetUploadTime(t time.Time) { r.CreatedAt = t }

// IPRequestCount holds the number of requests for a single IP on a date.
type IPRequestCount struct {
	CreatedAt time.Time  `bigquery:"created_at"`
	Date      civil.Date `bigquery:"date"` // year-month-day without a timezone
	IP        string     `bigquery:"ip"`   // obfuscated IP address
	Count     int        `bigquery:"count"`
}

// SetUploadTime is used by Client.Upload.
func (r *IPRequestCount) SetUploadTime(t time.Time) { r.CreatedAt = t }

// writeToBigQuery writes request counts to BigQuery.
func writeToBigQuery(ctx context.Context, client *bigquery.Client, rcs []*RequestCount, ircs []*IPRequestCount) (err error) {
	defer derrors.Wrap(&err, "vulndbreqs.writeToBigQuery")
	if _, err := client.CreateOrUpdateTable(ctx, RequestCountTableName); err != nil {
		return err
	}
	if err := bigquery.UploadMany(ctx, client, RequestCountTableName, rcs, 0); err != nil {
		return err
	}
	if _, err := client.CreateOrUpdateTable(ctx, IPRequestCountTableName); err != nil {
		return err
	}
	return bigquery.UploadMany(ctx, client, IPRequestCountTableName, ircs, 0)
}

// ReadRequestCountsFromBigQuery returns daily counts for requests to the vuln DB, most recent first.
func ReadRequestCountsFromBigQuery(ctx context.Context, client *bigquery.Client) (_ []*RequestCount, err error) {
	defer derrors.Wrap(&err, "readFromBigQuery")
	// Select the most recently inserted row for each date.
	q := fmt.Sprintf("(%s) ORDER BY date DESC", bigquery.PartitionQuery{
		From:        "`" + client.FullTableName(RequestCountTableName) + "`",
		PartitionOn: "date",
		OrderBy:     "created_at DESC",
	})
	iter, err := client.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return bigquery.All[RequestCount](iter)
}
