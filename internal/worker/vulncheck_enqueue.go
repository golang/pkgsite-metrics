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

// handleEnqueue enqueues multiple modules for a single vulncheck mode.
// Query params:
//   - suffix: appended to task queue IDs to generate unique tasks
//   - mode: type of analysis to run; see [modes]
//   - file: path to file containing modules; if missing, use DB
//   - min: minimum import-by count for a module to be included
func (h *VulncheckServer) handleEnqueue(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	suffix := r.FormValue("suffix")
	mode, err := vulncheckMode(scan.ParseMode(r))
	if err != nil {
		return err
	}

	var sreqs []*scan.Request
	if mode == ModeBinary {
		var err error
		sreqs, err = readBinaries(ctx, h.cfg.BinaryBucket)
		if err != nil {
			return err
		}
	} else {
		minImpCount, err := scan.ParseOptionalIntParam(r, "min", defaultMinImportedByCount)
		if err != nil {
			return err
		}
		modspecs, err := readModules(ctx, h.cfg, r.FormValue("file"), minImpCount)
		if err != nil {
			return err
		}
		sreqs = moduleSpecsToScanRequests(modspecs, mode)
	}
	return enqueueModules(ctx, sreqs, h.queue, &queue.Options{Namespace: "vulncheck", TaskNameSuffix: suffix})
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
	ctx := r.Context()
	suffix := r.FormValue("suffix")
	minImpCount, err := scan.ParseOptionalIntParam(r, "min", defaultMinImportedByCount)
	if err != nil {
		return err
	}
	modspecs, err := readModules(ctx, h.cfg, r.FormValue("file"), minImpCount)
	if err != nil {
		return err
	}
	opts := &queue.Options{Namespace: "vulncheck", TaskNameSuffix: suffix}
	for mode := range modes {
		var sreqs []*scan.Request
		if mode == ModeBinary {
			sreqs, err = readBinaries(ctx, h.cfg.BinaryBucket)
			if err != nil {
				return err
			}
		} else {
			sreqs = moduleSpecsToScanRequests(modspecs, mode)
		}
		if err := enqueueModules(ctx, sreqs, h.queue, opts); err != nil {
			return err
		}
	}
	return nil
}

// binaryDir is the directory in the GCS bucket that contains binaries that should be scanned.
const binaryDir = "binaries"

func readBinaries(ctx context.Context, bucketName string) (sreqs []*scan.Request, err error) {
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
		sreqs = append(sreqs, &scan.Request{
			ModuleURLPath: mp,
			RequestParams: scan.RequestParams{Mode: ModeBinary},
		})
	}
	return sreqs, nil
}
