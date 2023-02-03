// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"sync"

	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/pkgsitedb"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

const defaultMinImportedByCount = 10

func readModules(ctx context.Context, cfg *config.Config, file string, minImpCount int) ([]scan.ModuleSpec, error) {
	if file != "" {
		log.Infof(ctx, "reading modules from file %s", file)
		return scan.ParseCorpusFile(file, minImpCount)
	}
	log.Infof(ctx, "reading modules from DB %s", cfg.PkgsiteDBName)
	return readFromDB(ctx, cfg, minImpCount)
}

func readFromDB(ctx context.Context, cfg *config.Config, minImportedByCount int) ([]scan.ModuleSpec, error) {
	db, err := pkgsitedb.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return pkgsitedb.ModuleSpecs(ctx, db, minImportedByCount)
}

func enqueueModules(ctx context.Context, sreqs []*scan.Request, q queue.Queue, opts *queue.Options) (err error) {
	defer derrors.Wrap(&err, "enqueueModules")

	// Enqueue concurrently, because sequentially takes a while.
	const concurrentEnqueues = 10
	var (
		mu                 sync.Mutex
		nEnqueued, nErrors int
	)
	sem := make(chan struct{}, concurrentEnqueues)

	for _, sreq := range sreqs {
		log.Infof(ctx, "enqueuing: %s", sreq.URLPathAndParams())
		if sreq.Module == "std" {
			continue // ignore the standard library
		}
		sreq := sreq
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			enqueued, err := q.EnqueueScan(ctx, sreq, opts)
			mu.Lock()
			if err != nil {
				log.Errorf(ctx, "enqueuing: %v", err)
				nErrors++
			} else if enqueued {
				nEnqueued++
			}
			mu.Unlock()
		}()
	}
	// Wait for goroutines to finish.
	for i := 0; i < concurrentEnqueues; i++ {
		sem <- struct{}{}
	}
	log.Infof(ctx, "Successfully scheduled modules to be fetched: %d modules enqueued, %d errors", nEnqueued, nErrors)
	return nil
}

func moduleSpecsToScanRequests(modspecs []scan.ModuleSpec, mode string) []*scan.Request {
	var sreqs []*scan.Request
	for _, ms := range modspecs {
		sreqs = append(sreqs, &scan.Request{
			Module:     ms.Path,
			Version:    ms.Version,
			ImportedBy: ms.ImportedBy,
			Mode:       mode,
		})
	}
	return sreqs
}
