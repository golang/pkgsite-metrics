// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
	"google.golang.org/api/iterator"
)

// query params for vulncheck/enqueue
type vulncheckEnqueueParams struct {
	Suffix string // appended to task queue IDs to generate unique tasks
	Mode   string // type of analysis to run
	Min    int    // minimum import-by count for a module to be included
	File   string // path to file containing modules; if missing, use DB
}

// handleEnqueue enqueues multiple modules for a single vulncheck mode.
func (h *VulncheckServer) handleEnqueue(w http.ResponseWriter, r *http.Request) error {
	params := &vulncheckEnqueueParams{Min: defaultMinImportedByCount}
	if err := scan.ParseParams(r, &params); err != nil {
		return err
	}
	ctx := r.Context()
	mode, err := vulncheckMode(params.Mode)
	if err != nil {
		return err
	}

	var reqs []*vulncheckRequest
	if mode == ModeBinary {
		var err error
		reqs, err = readBinaries(ctx, h.cfg.BinaryBucket)
		if err != nil {
			return err
		}
	} else {
		modspecs, err := readModules(ctx, h.cfg, params.File, params.Min)
		if err != nil {
			return err
		}
		reqs = moduleSpecsToScanRequests(modspecs, mode)
	}
	var sreqs []queue.Task
	for _, req := range reqs {
		if req.Module != "std" { // ignore the standard library
			sreqs = append(sreqs, req)
		}
	}
	return enqueueTasks(ctx, sreqs, h.queue,
		&queue.Options{Namespace: "vulncheck", TaskNameSuffix: params.Suffix})
}

func vulncheckMode(mode string) (string, error) {
	if mode == "" {
		// VTA is the default mode
		return ModeVTA, nil
	}
	mode = strings.ToUpper(mode)
	if _, ok := modes[mode]; !ok {
		return "", fmt.Errorf("unsupported mode: %v", mode)
	}
	return mode, nil
}

// handleEnqueueAll enqueues multiple modules for all vulncheck modes.
// Query params:
//   - suffix: appended to task queue IDs to generate unique tasks
//   - file: path to file containing modules; if missing, use DB
//   - min: minimum import-by count for a module to be included
func (h *VulncheckServer) handleEnqueueAll(w http.ResponseWriter, r *http.Request) error {
	params := &vulncheckEnqueueParams{Min: defaultMinImportedByCount}
	if err := scan.ParseParams(r, &params); err != nil {
		return err
	}

	ctx := r.Context()
	modspecs, err := readModules(ctx, h.cfg, params.File, params.Min)
	if err != nil {
		return err
	}
	opts := &queue.Options{Namespace: "vulncheck", TaskNameSuffix: params.Suffix}
	for mode := range modes {
		var reqs []*vulncheckRequest
		if mode == ModeBinary {
			reqs, err = readBinaries(ctx, h.cfg.BinaryBucket)
			if err != nil {
				return err
			}
		} else {
			reqs = moduleSpecsToScanRequests(modspecs, mode)
		}
		var tasks []queue.Task
		for _, req := range reqs {
			if req.Module != "std" { // ignore the standard library
				tasks = append(tasks, req)
			}
		}
		if err := enqueueTasks(ctx, tasks, h.queue, opts); err != nil {
			return err
		}
	}
	return nil
}

// binaryDir is the directory in the GCS bucket that contains binaries that should be scanned.
const binaryDir = "binaries"

func readBinaries(ctx context.Context, bucketName string) (reqs []*vulncheckRequest, err error) {
	defer derrors.Wrap(&err, "readBinaries(%q)", bucketName)
	if bucketName == "" {
		log.Infof(ctx, "binary bucket not configured; not enqueuing binaries")
		return nil, nil
	}
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	iter := c.Bucket(bucketName).Objects(ctx, &storage.Query{Prefix: binaryDir})
	for {
		attrs, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mp, err := scan.ParseModuleURLPath(strings.TrimPrefix(attrs.Name, binaryDir+"/"))
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, &vulncheckRequest{
			ModuleURLPath:          mp,
			vulncheckRequestParams: vulncheckRequestParams{Mode: ModeBinary},
		})
	}
	return reqs, nil
}
