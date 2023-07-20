// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jobs supports jobs, which are collections of enqueued tasks.
package jobs

import (
	"time"

	"golang.org/x/pkgsite-metrics/internal/analysis"
)

// A Job is a set of related scan tasks enqueued at the same time.
type Job struct {
	User          string
	StartedAt     time.Time
	URL           string // The URL that initiated the job.
	Binary        string // Name of binary.
	BinaryVersion string // Hex-encoded hash of binary.
	BinaryArgs    string // The args to the binary.
	Canceled      bool   // The job was canceled.
	// Counts of tasks.
	NumEnqueued  int // Written by enqueue endpoint.
	NumStarted   int // Incremented at the start of a scan.
	NumSkipped   int // Previously run, stored in BigQuery.
	NumFailed    int // The HTTP request failed (status != 200)
	NumErrored   int // The HTTP request succeeded, but the scan resulted in an error.
	NumSucceeded int
}

// NewJob creates a new Job.
func NewJob(user string, start time.Time, url, binaryName, binaryVersion, binaryArgs string) *Job {
	return &Job{
		User:          user,
		StartedAt:     start,
		URL:           url,
		Binary:        binaryName,
		BinaryVersion: binaryVersion,
		BinaryArgs:    binaryArgs,
	}
}

const startTimeFormat = "060102-150405" // YYMMDD-HHMMSS, UTC

// ID returns a unique identifier for a job which can serve as a database key.
func (j *Job) ID() string {
	return j.User + "-" + j.StartedAt.In(time.UTC).Format(startTimeFormat)
}

func (j *Job) NumFinished() int {
	return j.NumSkipped + j.NumFailed + j.NumErrored + j.NumSucceeded
}

// Results hold the results of a job.
type Results struct {
	JobID   string
	Table   string // bigquery table containing results
	Results []*analysis.Result
}
