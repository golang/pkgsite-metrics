// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/jobs"
)

func TestJobs(t *testing.T) {
	ctx := context.Background()
	db := &testJobDB{map[string]*jobs.Job{}}
	tm := time.Date(2023, 3, 11, 1, 2, 3, 0, time.UTC)
	job := jobs.NewJob("user", tm, "url")
	if err := db.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := processJobRequest(ctx, &buf, "/describe", job.ID(), db); err != nil {
		t.Fatal(err)
	}

	var got jobs.Job
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(&got, job) {
		t.Errorf("got\n%+v\nwant\n%+v", got, job)
	}

	if err := processJobRequest(ctx, &buf, "/cancel", job.ID(), db); err != nil {
		t.Fatal(err)
	}

	got2, err := db.GetJob(ctx, job.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Canceled {
		t.Error("got canceled false, want true")
	}
}

type testJobDB struct {
	jobs map[string]*jobs.Job
}

func (d *testJobDB) CreateJob(ctx context.Context, j *jobs.Job) error {
	id := j.ID()
	if _, ok := d.jobs[id]; ok {
		return fmt.Errorf("job with id %q exists", id)
	}
	d.jobs[id] = j
	return nil
}

func (d *testJobDB) DeleteJob(ctx context.Context, id string) error {
	delete(d.jobs, id)
	return nil
}

func (d *testJobDB) GetJob(ctx context.Context, id string) (*jobs.Job, error) {
	j, ok := d.jobs[id]
	if !ok {
		return nil, fmt.Errorf("job with id %q: %w", id, derrors.NotFound)
	}
	// Copy job so a client in the same process can't modify it.
	j2 := *j
	return &j2, nil
}

func (d *testJobDB) UpdateJob(ctx context.Context, id string, f func(*jobs.Job) error) error {
	j, err := d.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if err := f(j); err != nil {
		return err
	}
	d.jobs[id] = j
	return nil
}
