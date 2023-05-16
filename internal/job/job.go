// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package job supports jobs, collections of enqueued tasks.
package job

import (
	"time"
)

// A Job is a set of related scan tasks enqueued at the same time.
type Job struct {
	User      string
	StartedAt time.Time
	URL       string // The URL that initiated the job.
	Canceled  bool   // The job was canceled.
	// Counts of tasks.
	NumEnqueued  int // Written by enqueue endpoint.
	NumStarted   int // Incremented at the start of a scan.
	NumCached    int // Previously run, stored in BigQuery.
	NumFailed    int // The HTTP request failed (status != 200)
	NumErrored   int // The HTTP request succeeded, but the scan resulted in an error.
	NumSucceeded int
}

// New creates a new Job.
func New(user string, start time.Time, url string) *Job {
	return &Job{
		User:      user,
		StartedAt: start,
		URL:       url,
	}
}

const startTimeFormat = "060102-030405" // YYMMDD-HHMMSS, UTC

func (j *Job) ID() string {
	return j.User + "-" + j.StartedAt.In(time.UTC).Format(startTimeFormat)
}
