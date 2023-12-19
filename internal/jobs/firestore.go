// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jobs

import (
	"context"
	"time"

	"cloud.google.com/go/firestore"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/fstore"
	"google.golang.org/api/iterator"
)

const jobCollection = "Jobs"

type DB struct {
	ns *fstore.Namespace
}

// NewDB creates a new database client for jobs.
func NewDB(ctx context.Context, projectID, namespace string) (_ *DB, err error) {
	ns, err := fstore.OpenNamespace(ctx, projectID, namespace)
	if err != nil {
		return nil, err
	}
	return &DB{ns}, nil
}

// CreateJob creates a new job. It returns an error if a job with the same ID already exists.
func (d *DB) CreateJob(ctx context.Context, j *Job) (err error) {
	id := j.ID()
	defer derrors.Wrap(&err, "job.DB.CreateJob(%s)", id)
	_, err = d.jobRef(id).Create(ctx, j)
	return err
}

// DeleteJob deletes the job with the given ID. It does not return an error if the job doesn't exist.
func (d *DB) DeleteJob(ctx context.Context, id string) (err error) {
	defer derrors.Wrap(&err, "job.DB.DeleteJob(%s)", id)
	_, err = d.jobRef(id).Delete(ctx)
	return err
}

// GetJob retrieves the job with the given ID. It returns an error if the job does not exist.
func (d *DB) GetJob(ctx context.Context, id string) (_ *Job, err error) {
	defer derrors.Wrap(&err, "job.DB.GetJob(%s)", id)
	return fstore.Get[Job](ctx, d.jobRef(id))
}

// UpdateJob gets the job with the given ID, which must exist, then calls f on
// it, then writes it back to the database. These actions occur atomically.
// If f returns an error, that error is returned and no update occurs.
func (d *DB) UpdateJob(ctx context.Context, id string, f func(*Job) error) (err error) {
	defer derrors.Wrap(&err, "job.DB.UpdateJob(%s)", id)
	return d.ns.Client().RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		docref := d.jobRef(id)
		docsnap, err := tx.Get(docref)
		if err != nil {
			return err
		}
		j, err := fstore.Decode[Job](docsnap)
		if err != nil {
			return err
		}
		if err := f(j); err != nil {
			return err
		}
		return tx.Set(docref, j)
	},
		firestore.MaxAttempts(firestore.DefaultTransactionMaxAttempts*5))
}

// Increment value named name by n.
func (d *DB) Increment(ctx context.Context, id, name string, n int) (err error) {
	defer derrors.Wrap(&err, "job.DB.Increment(%s)", id)
	docref := d.jobRef(id)
	_, err = docref.Update(ctx, []firestore.Update{
		{Path: name, Value: firestore.Increment(n)}, // name will incremented by n
	})
	return err
}

// ListJobs calls f on each job in the DB, most recently started first.
// f is also passed the time that the job was last updated.
// If f returns a non-nil error, the iteration stops and returns that error.
func (d *DB) ListJobs(ctx context.Context, f func(_ *Job, lastUpdate time.Time) error) (err error) {
	defer derrors.Wrap(&err, "job.DB.ListJobs()")

	q := d.ns.Collection(jobCollection).OrderBy("StartedAt", firestore.Desc)
	iter := q.Documents(ctx)
	defer iter.Stop()
	for {
		docsnap, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		job, err := fstore.Decode[Job](docsnap)
		if err != nil {
			return err
		}
		if err := f(job, docsnap.UpdateTime); err != nil {
			return err
		}
	}
	return nil
}

// jobRef returns the DocumentRef for a job with the given ID.
func (d *DB) jobRef(id string) *firestore.DocumentRef {
	return d.ns.Collection(jobCollection).Doc(id)
}
