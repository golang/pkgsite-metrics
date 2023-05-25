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
	"strings"
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
	path = strings.TrimPrefix(path, "/jobs/")
	switch path {
	case "describe": // describe one job
		if jobID == "" {
			return fmt.Errorf("missing jobid: %w", derrors.InvalidArgument)
		}
		job, err := db.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		return writeJSON(w, job)

	case "cancel":
		if jobID == "" {
			return fmt.Errorf("missing jobid: %w", derrors.InvalidArgument)
		}
		return db.UpdateJob(ctx, jobID, func(j *jobs.Job) error {
			j.Canceled = true
			return nil
		})

	case "list":
		var joblist []*jobs.Job
		err := db.ListJobs(ctx, func(j *jobs.Job, _ time.Time) error {
			joblist = append(joblist, j)
			return nil
		})
		if err != nil {
			return err
		}
		return writeJSON(w, joblist)

	default:
		return fmt.Errorf("unknown path %q: %w", path, derrors.InvalidArgument)
	}
}

// writeJSON JSON-marshals v and writes it to w.
// Marshal failures do not result in partial writes.
func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}
