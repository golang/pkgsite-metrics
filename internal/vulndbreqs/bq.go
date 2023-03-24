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
	DatasetName = "vulndb"
	TableName   = "requests"
)

func init() {
	s, err := bigquery.InferSchema(RequestCount{})
	if err != nil {
		panic(err)
	}
	bigquery.AddTable(TableName, s)
}

// RequestCount is a row in the BigQuery table.
type RequestCount struct {
	CreatedAt time.Time  `bigquery:"created_at"`
	Date      civil.Date `bigquery:"date"` // year-month-day without a timezone
	Count     int        `bigquery:"count"`
}

// SetUploadTime is used by Client.Upload.
func (r *RequestCount) SetUploadTime(t time.Time) { r.CreatedAt = t }

// writeToBigQuery writes a list of RequestCounts to BigQuery.
func writeToBigQuery(ctx context.Context, client *bigquery.Client, rcs []*RequestCount) (err error) {
	defer derrors.Wrap(&err, "vulndbreqs.writeToBigQuery")
	if err := client.CreateTable(ctx, TableName); err != nil {
		return err
	}
	return bigquery.UploadMany(ctx, client, TableName, rcs, 0)
}

// readFromBigQuery returns daily counts for requests to the vuln DB, most recent first.
func readFromBigQuery(ctx context.Context, client *bigquery.Client) (_ []*RequestCount, err error) {
	defer derrors.Wrap(&err, "readFromBigQuery")
	// Select the most recently inserted row for each date.
	q := fmt.Sprintf("(%s) ORDER BY date DESC", bigquery.PartitionQuery{
		Table:       client.FullTableName(TableName),
		PartitionOn: "date",
		OrderBy:     "created_at DESC",
	})
	iter, err := client.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return bigquery.All[RequestCount](iter)
}
