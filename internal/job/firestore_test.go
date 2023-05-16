// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package job

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

var project = flag.String("project", "", "GCP project for Firestore")

func TestDB(t *testing.T) {
	test.NeedsIntegrationEnv(t)
	if *project == "" {
		t.Skip("missing -project")
	}
	ctx := context.Background()
	db, err := NewDB(ctx, *project, "testing")
	if err != nil {
		t.Fatal(err)
	}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	tm := time.Date(2001, 02, 03, 4, 5, 6, 0, time.UTC)
	job := New("user", tm, "analysis/enqueue?min=10")

	// Make sure the job doesn't exist. Delete doesn't fail
	// in that case.
	must(db.DeleteJob(ctx, job.ID()))

	// Create a new job.
	must(db.CreateJob(ctx, job))

	// Get it and make sure it's the same.
	got, err := db.GetJob(ctx, job.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(got, job) {
		t.Errorf("got\n%+v\nwant\n%+v", got, job)
	}

	// Update it.
	must(db.UpdateJob(ctx, job.ID(), func(j *Job) error {
		j.NumStarted++
		j.NumSucceeded++
		return nil
	}))

	job.NumStarted = 1
	job.NumSucceeded = 1
	got, err = db.GetJob(ctx, job.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(got, job) {
		t.Errorf("got\n%+v\nwant\n%+v", got, job)
	}
}
