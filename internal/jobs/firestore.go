// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jobs

import (
	"context"
	"errors"

	"cloud.google.com/go/firestore"
	"golang.org/x/pkgsite-metrics/internal/derrors"
)

// A DB is a client for a database that stores Jobs.
type DB struct {
	namespace string
	client    *firestore.Client
	nsDoc     *firestore.DocumentRef // the namespace for this db
}

const (
	namespaceCollection = "Namespaces"
	jobCollection       = "Jobs"
)

// NewDB creates a new database client for jobs.
func NewDB(ctx context.Context, projectID, namespace string) (_ *DB, err error) {
	defer derrors.Wrap(&err, "job.NewDB(%q, %q)", projectID, namespace)

	if namespace == "" {
		return nil, errors.New("empty namespace")
	}
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &DB{
		namespace: namespace,
		client:    client,
		nsDoc:     client.Collection(namespaceCollection).Doc(namespace),
	}, nil
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
	docsnap, err := d.jobRef(id).Get(ctx)
	if err != nil {
		return nil, err
	}
	return docsnapToJob(docsnap)
}

// UpdateJob gets the job with the given ID, which must exist, then calls f on
// it, then writes it back to the database. These actions occur atomically.
// If f returns an error, that error is returned and no update occurs.
func (d *DB) UpdateJob(ctx context.Context, id string, f func(*Job) error) (err error) {
	defer derrors.Wrap(&err, "job.DB.UpdateJob(%s)", id)
	return d.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		docref := d.jobRef(id)
		docsnap, err := tx.Get(docref)
		if err != nil {
			return err
		}
		j, err := docsnapToJob(docsnap)
		if err != nil {
			return err
		}
		if err := f(j); err != nil {
			return err
		}
		return tx.Set(docref, j)
	})
}

// jobRef returns the DocumentRef for a job with the given ID.
func (d *DB) jobRef(id string) *firestore.DocumentRef {
	return d.nsDoc.Collection(jobCollection).Doc(id)
}

// docsnapToJob converts a DocumentSnapshot to a Job.
func docsnapToJob(ds *firestore.DocumentSnapshot) (*Job, error) {
	var j Job
	if err := ds.DataTo(&j); err != nil {
		return nil, err
	}
	return &j, nil
}
