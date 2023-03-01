// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Track daily counts of requests made to vuln.go.dev in BigQuery.

package bigquery

import (
	"context"
	"fmt"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"golang.org/x/pkgsite-metrics/internal/derrors"
)

const (
	// Vuln DB requests live in their own dataset that doesn't vary.
	VulnDBRequestDatasetName = "vulndb"
	VulnDBRequestTableName   = "requests"
)

type VulnDBRequestCount struct {
	Date       civil.Date `bigquery:"date"`
	Count      int        `bigquery:"count"`
	InsertedAt time.Time  `bigquery:"inserted_at"`
}

func init() {
	s, err := bq.InferSchema(VulnDBRequestCount{})
	if err != nil {
		panic(err)
	}
	AddTable(VulnDBRequestTableName, s)
}

// SetUploadTime is used by Client.Upload.
func (v *VulnDBRequestCount) SetUploadTime(t time.Time) { v.InsertedAt = t }

func WriteVulnDBRequestCounts(ctx context.Context, projectID string, rcs []*VulnDBRequestCount) (err error) {
	defer derrors.Wrap(&err, "WriteVulnDBRequestCounts(%s)", projectID)
	c, err := NewClientCreate(ctx, projectID, VulnDBRequestDatasetName)
	if err != nil {
		return err
	}
	if err := c.CreateTable(ctx, VulnDBRequestTableName); err != nil {
		return err
	}
	return UploadMany(ctx, c, VulnDBRequestTableName, rcs, 0)
}

// ReadVulnDBRequestCounts returns daily counts for requests to the vuln DB, with the most recent first.
func ReadVulnDBRequestCounts(ctx context.Context, projectID string) (_ []*VulnDBRequestCount, err error) {
	defer derrors.Wrap(&err, "ReadVulnDBRequestCounts(%s)", projectID)

	c, err := NewClient(ctx, projectID, VulnDBRequestDatasetName)
	if err != nil {
		return nil, err
	}
	return readVulnDBRequestCounts(ctx, c)
}

func readVulnDBRequestCounts(ctx context.Context, c *Client) (_ []*VulnDBRequestCount, err error) {
	// Select the most recently inserted row for each date.
	q := fmt.Sprintf("(%s) ORDER BY date DESC",
		PartitionQuery(c.FullTableName(VulnDBRequestTableName), "date", "inserted_at DESC"))
	iter, err := c.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	counts, err := All[VulnDBRequestCount](iter)
	if err != nil {
		return nil, err
	}
	return counts, nil
}
