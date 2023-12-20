// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fstore provides general support for Firestore.
// Its main feature is separate namespaces, to mimic separate
// databases for different purposes (prod, dev, test, etc.).
package fstore

import (
	"context"
	"errors"

	"cloud.google.com/go/firestore"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const namespaceCollection = "Namespaces"

// A Namespace is a top-level collection for partitioning a Firestore
// database into separate segments.
type Namespace struct {
	client *firestore.Client
	name   string
	doc    *firestore.DocumentRef
}

// OpenNamespace creates a new Firestore client whose collections will be located in the given namespace.
func OpenNamespace(ctx context.Context, projectID, name string) (_ *Namespace, err error) {
	defer derrors.Wrap(&err, "OpenNamespace(%q, %q)", projectID, name)

	if name == "" {
		return nil, errors.New("empty namespace")
	}
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &Namespace{
		client: client,
		name:   name,
		doc:    client.Collection(namespaceCollection).Doc(name),
	}, nil
}

// Name returns the Namespace's name.
func (ns *Namespace) Name() string { return ns.name }

// Client returns the underlying Firestore client.
func (ns *Namespace) Client() *firestore.Client { return ns.client }

// Close closes the underlying client.
func (ns *Namespace) Close() error { return ns.client.Close() }

// Collection returns a reference to the named collection in the namespace.
func (ns *Namespace) Collection(name string) *firestore.CollectionRef {
	return ns.doc.Collection(name)
}

// Get gets the DocumentRef and decodes the result to a value of type T.
func Get[T any](ctx context.Context, dr *firestore.DocumentRef) (_ *T, err error) {
	defer derrors.Wrap(&err, "fstore.Get(%q)", dr.Path)
	docsnap, err := dr.Get(ctx)
	if err != nil {
		return nil, convertError(err)
	}
	return Decode[T](docsnap)
}

// Set sets the DocumentRef to the value.
func Set[T any](ctx context.Context, dr *firestore.DocumentRef, value *T) (err error) {
	defer derrors.Wrap(&err, "firestore.Set(%q)", dr.Path)
	_, err = dr.Set(ctx, value)
	return convertError(err)
}

// Decode decodes a DocumentSnapshot into a value of type T.
func Decode[T any](ds *firestore.DocumentSnapshot) (*T, error) {
	var t T
	if err := ds.DataTo(&t); err != nil {
		return nil, convertError(err)
	}
	return &t, nil
}

// convertError converts err into one of this module's error kinds
// if possible.
func convertError(err error) error {
	serr, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch serr.Code() {
	case codes.NotFound:
		return derrors.NotFound
	case codes.InvalidArgument:
		return derrors.InvalidArgument
	default:
		return err
	}
}
