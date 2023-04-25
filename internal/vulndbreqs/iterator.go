// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulndbreqs

import (
	"context"
	"time"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
	"golang.org/x/pkgsite-metrics/internal/log"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// entryIterator wraps a logadmin.EntryIterator to handle quota limits.
// When it sees a ResourceExhausted error, it waits a few seconds to
// get more quota.
type entryIterator struct {
	ctx    context.Context
	client *logadmin.Client
	filter string
	it     *logadmin.EntryIterator
	count  int
	token  string
}

func newEntryIterator(ctx context.Context, client *logadmin.Client, filter string) *entryIterator {
	return &entryIterator{ctx: ctx, client: client, filter: filter}
}

func (it *entryIterator) Next() (*logging.Entry, error) {
	for {
		if it.it == nil {
			it.it = it.client.Entries(it.ctx, logadmin.Filter(it.filter))
			pi := it.it.PageInfo()
			// Using a large page size results in fewer requests to the logging API.
			// 1000 is the maximum allowed.
			pi.MaxSize = 1000
			// If we remembered a page token, start the iterator with it.
			// See [google.golang.org/api/iterator.PageInfo].
			if it.token != "" {
				pi.Token = it.token
			}
			it.count = 0
		}
		entry, err := it.it.Next()
		if err == iterator.Done {
			return nil, err
		}
		if s, ok := status.FromError(err); ok && s.Code() == codes.ResourceExhausted {
			// We ran out of quota. Wait a little and try again.
			log.Infof(it.ctx, "entryIterator: got ResourceExhausted after reading %d entries, sleeping...:\n%v", it.count, err)
			time.Sleep(10 * time.Second)
			log.Infof(it.ctx, "entryIterator: retrying")
			it.token = it.it.PageInfo().Token
			// We can't continue with this iterator, so create a new one at the
			// top of the loop.
			it.it = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		it.count++
		return entry, nil
	}
}
