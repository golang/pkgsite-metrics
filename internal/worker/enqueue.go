// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"math"
	"sync"

	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/pkgsitedb"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

const (
	defaultMinImportedByCount = 10
	defaultMaxImportedByCount = math.MaxInt32
)

func readModules(ctx context.Context, cfg *config.Config, file string, minImports, maxImports int32) ([]scan.ModuleSpec, error) {
	if file != "" {
		log.Infof(ctx, "reading modules from file %s", file)
		return scan.ParseCorpusFile(file, minImports, maxImports)
	}
	log.Infof(ctx, "reading modules from DB %s", cfg.PkgsiteDBName)
	return readFromDB(ctx, cfg, minImports, maxImports)
}

func readFromDB(ctx context.Context, cfg *config.Config, minImports, maxImports int32) ([]scan.ModuleSpec, error) {
	db, err := pkgsitedb.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return pkgsitedb.ModuleSpecs(ctx, db, minImports, maxImports)
}

func enqueueTasks(ctx context.Context, tasks []queue.Task, q queue.Queue, opts *queue.Options) (err error) {
	defer derrors.Wrap(&err, "enqueueTasks")

	// Enqueue concurrently, because sequentially takes a while.
	const concurrentEnqueues = 20
	var (
		mu                 sync.Mutex
		nEnqueued, nErrors int
	)
	sem := make(chan struct{}, concurrentEnqueues)

	for _, sreq := range tasks {
		log.Infof(ctx, "enqueuing: %s?%s", sreq.Path(), sreq.Params())
		sreq := sreq
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			enqueued, err := q.EnqueueScan(ctx, sreq, opts)
			mu.Lock()
			if err != nil {
				log.Errorf(ctx, err, "enqueuing")
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
