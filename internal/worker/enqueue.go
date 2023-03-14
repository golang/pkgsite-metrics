// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"sync"

	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
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

func enqueueTasks(ctx context.Context, tasks []queue.Task, q queue.Queue, opts *queue.Options) (err error) {
	defer derrors.Wrap(&err, "enqueueTasks")

	// Enqueue concurrently, because sequentially takes a while.
	const concurrentEnqueues = 10
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

func moduleSpecsToScanRequests(modspecs []scan.ModuleSpec, mode string) []*govulncheck.Request {
	var sreqs []*govulncheck.Request
	for _, ms := range modspecs {
		sreqs = append(sreqs, &govulncheck.Request{
			ModuleURLPath: scan.ModuleURLPath{
				Module:  ms.Path,
				Version: ms.Version,
			},
			QueryParams: govulncheck.QueryParams{
				ImportedBy: ms.ImportedBy,
				Mode:       mode,
			},
		})
	}
	return sreqs
}
