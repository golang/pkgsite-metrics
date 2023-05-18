// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Handlers for jobs.
//
// jobs/describe?jobid=xxx		describe a job

// TODO:
// jobs/list					list all jobs
// jobs/cancel?jobid=xxx		cancel a job
// jobs/delete?jobid=xxx		delete a job
// jobs/deleteOlder?dur=xxx		delete jobs older than a duration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/jobs"
)

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "Server.handleJobs")
	ctx := r.Context()

	if s.jobDB == nil {
		return &serverError{err: errors.New("jobs DB not configured"), status: http.StatusNotImplemented}
	}

	jobID := r.FormValue("jobid")
	return processJobRequest(ctx, w, r.URL.Path, jobID, s.jobDB)
}

type jobDB interface {
	CreateJob(ctx context.Context, j *jobs.Job) error
	DeleteJob(ctx context.Context, id string) error
	GetJob(ctx context.Context, id string) (*jobs.Job, error)
	UpdateJob(ctx context.Context, id string, f func(*jobs.Job) error) error
	ListJobs(context.Context, func(*jobs.Job, time.Time) error) error
}

func processJobRequest(ctx context.Context, w io.Writer, path, jobID string, db jobDB) error {
	switch path {
	case "/describe": // describe one job
		if jobID == "" {
			return fmt.Errorf("missing jobid: %w", derrors.InvalidArgument)
		}
		job, err := db.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		enc.Encode(job)
		return nil

	case "/cancel":
		if jobID == "" {
			return fmt.Errorf("missing jobid: %w", derrors.InvalidArgument)
		}
		return db.UpdateJob(ctx, jobID, func(j *jobs.Job) error {
			j.Canceled = true
			return nil
		})

	case "/list":
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "%-20s\tEnq\tCompl\tCanceled\n", "ID")
		err := db.ListJobs(ctx, func(j *jobs.Job, _ time.Time) error {
			_, err := fmt.Fprintf(&buf, "%-20s\t%3d\t%3d\t%t\n",
				j.ID(), j.NumEnqueued, j.NumFailed+j.NumErrored+j.NumSucceeded,
				j.Canceled)
			return err
		})
		if err != nil {
			return err
		}
		buf.WriteTo(w)
		return nil

	default:
		return fmt.Errorf("unknown path %q: %w", path, derrors.InvalidArgument)
	}
}
