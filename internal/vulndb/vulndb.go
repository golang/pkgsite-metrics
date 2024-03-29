// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vulndb provides functionality for manipulating
// inputs and outputs of vulndb endpoint.
package vulndb

import (
	"context"
	"time"

	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/osv"
)

// Definitions for BigQuery.

// SchemaVersion changes whenever the BigQuery vulndb schema changes.
var SchemaVersion string

func init() {
	s, err := bigquery.InferSchema(Entry{})
	if err != nil {
		panic(err)
	}
	SchemaVersion = bigquery.SchemaVersion(s)
	bigquery.AddTable(TableName, s)
}

const (
	// Vuln DB requests live in their own dataset that doesn't vary.
	// This is the same database the vulnbreqs endpoint uses.
	DatasetName = "vulndb"
	TableName   = "vulndb"
)

// Entry is a row stored in a table. It follows the core
// structure of osv.Entry.
type Entry struct {
	CreatedAt time.Time `bigquery:"created_at"`

	ModifiedTime  time.Time `bigquery:"modified_time"`
	PublishedTime time.Time `bigquery:"published_time"`
	WithdrawnTime time.Time `bigquery:"withdrawn_time"`

	ID string `bigquery:"id"`

	// Modules can in principle have multiple entries
	// with the same path.
	Modules []Module `bigquery:"modules"`
}

func (e *Entry) SetUploadTime(t time.Time) { e.CreatedAt = t }

// Module plays the role of osv.Affected. The latter also has
// a Module field (among others), but we merge them into one
// type to avoid nesting which can make the queries more complex.
type Module struct {
	Path string `bigquery:"path"`
	// Ranges field plays the role of osv.Range type
	// where “SEMVER” range kind is assumed.
	Ranges []Range `bigquery:"ranges"`
}

// Range plays the role of osv.RangeEvent. That is, it is
// a list of versions representing the ranges in which the
// module is vulnerable. The events should be sorted, and
// MUST represent non-overlapping ranges.
type Range struct {
	Introduced string `bigquery:"introduced"`
	Fixed      string `bigquery:"fixed"`
}

func Convert(oe *osv.Entry) *Entry {
	e := &Entry{
		ID:            oe.ID,
		ModifiedTime:  oe.Modified,
		PublishedTime: oe.Published,
		Modules:       modules(oe),
	}
	if oe.Withdrawn != nil {
		e.WithdrawnTime = *oe.Withdrawn
	}
	return e
}

func modules(oe *osv.Entry) []Module {
	var modules []Module
	for _, a := range oe.Affected {
		modules = append(modules, Module{
			Path:   a.Module.Path,
			Ranges: ranges(a),
		})
	}
	return modules
}

func ranges(a osv.Affected) []Range {
	var rs []Range
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			rs = append(rs, Range{
				Introduced: e.Introduced,
				Fixed:      e.Fixed,
			})
		}
	}
	return rs
}

// ReadMostRecentDB returns entries from the table that reflect the
// most recent state of the vulnerability database at c.
func ReadMostRecentDB(ctx context.Context, c *bigquery.Client) (entries []*Entry, err error) {
	defer derrors.Wrap(&err, "ReadMostRecentDB")

	// The server does not create vulndb table since it lives
	// in a different dataset. Hence, one could get an error
	// accessing it if it was not created in the past.
	if _, err := c.CreateOrUpdateTable(ctx, TableName); err != nil {
		return nil, err
	}

	query := bigquery.PartitionQuery{
		From:        "`" + c.FullTableName(TableName) + "`",
		PartitionOn: "ID",
		OrderBy:     "modified_time DESC",
	}.String()
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	err = bigquery.ForEachRow(iter, func(e *Entry) bool {
		entries = append(entries, e)
		return true
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}
