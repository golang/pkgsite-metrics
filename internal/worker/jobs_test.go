// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
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
	job := jobs.NewJob("user", tm, "url", "bin", "<hash>", "args go here")
	if err := db.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	var buf bytes.Buffer
	if err := s.processJobRequest(ctx, &buf, "/jobs/describe", job.ID(), "false", db); err != nil {
		t.Fatal(err)
	}

	var got jobs.Job
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(&got, job) {
		t.Errorf("got\n%+v\nwant\n%+v", got, job)
	}

	if err := s.processJobRequest(ctx, &buf, "/jobs/cancel", job.ID(), "false", db); err != nil {
		t.Fatal(err)
	}

	got2, err := db.GetJob(ctx, job.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Canceled {
		t.Error("got canceled false, want true")
	}

	buf.Reset()
	if err := s.processJobRequest(ctx, &buf, "/jobs/list", "", "", db); err != nil {
		t.Fatal(err)
	}
	// Don't check for specific output, just make sure there's something
	// that mentions the job user.
	got3 := buf.String()
	if !strings.Contains(got3, job.User) {
		t.Errorf("got\n%q\nwhich does not contain the job user %q", got3, job.User)
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

func (d *testJobDB) ListJobs(ctx context.Context, f func(*jobs.Job, time.Time) error) error {
	// Sort by StartedAt descending.
	sortedJobs := slices.SortedFunc(maps.Values(d.jobs), func(j1, j2 *jobs.Job) int {
		return -1 * j1.StartedAt.Compare(j2.StartedAt)
	})
	for _, j := range sortedJobs {
		if err := f(j, time.Time{}); err != nil {
			return err
		}
	}
	return nil
}
