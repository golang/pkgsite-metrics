// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/exp/maps"
	"golang.org/x/pkgsite-metrics/internal/config"
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
	return h.enqueue(r, false)
}

// handleEnqueueAll enqueues multiple modules for all vulncheck modes.
func (h *VulncheckServer) handleEnqueueAll(w http.ResponseWriter, r *http.Request) error {
	return h.enqueue(r, true)
}

func (h *VulncheckServer) enqueue(r *http.Request, allModes bool) error {
	tasks, params, err := createVulncheckQueueTasks(r, h.cfg, allModes)
	if err != nil {
		return err
	}
	return enqueueTasks(r.Context(), tasks, h.queue,
		&queue.Options{Namespace: "vulncheck", TaskNameSuffix: params.Suffix})
}

func createVulncheckQueueTasks(r *http.Request, cfg *config.Config, allModes bool) (_ []queue.Task, _ *vulncheckEnqueueParams, err error) {
	defer derrors.Wrap(&err, "createQueueTasks(%s, %t)", r.URL, allModes)
	ctx := r.Context()
	params := &vulncheckEnqueueParams{Min: defaultMinImportedByCount}
	if err := scan.ParseParams(r, params); err != nil {
		return nil, nil, err
	}
	if allModes && params.Mode != "" {
		return nil, nil, errors.New("mode query param provided for enqueueAll")
	}
	var enqueueModes []string
	if allModes {
		enqueueModes = maps.Keys(modes)
		sort.Strings(enqueueModes) // make deterministic for testing
	} else {
		mode, err := vulncheckMode(params.Mode)
		if err != nil {
			return nil, nil, err
		}
		enqueueModes = []string{mode}
	}

	var (
		tasks    []queue.Task
		modspecs []scan.ModuleSpec
	)
	for _, mode := range enqueueModes {
		var reqs []*vulncheckRequest
		if mode == ModeBinary {
			reqs, err = readBinaries(ctx, cfg.BinaryBucket)
			if err != nil {
				return nil, nil, err
			}
		} else {
			if modspecs == nil {
				modspecs, err = readModules(ctx, cfg, params.File, params.Min)
				if err != nil {
					return nil, nil, err
				}
			}
			reqs = moduleSpecsToScanRequests(modspecs, mode)
		}
		for _, req := range reqs {
			if req.Module != "std" { // ignore the standard library
				tasks = append(tasks, req)
			}
		}
	}
	return tasks, params, nil
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
