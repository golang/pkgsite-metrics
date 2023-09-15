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

	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

// handleEnqueue enqueues multiple modules for a single govulncheck mode.
func (h *GovulncheckServer) handleEnqueue(w http.ResponseWriter, r *http.Request) error {
	return h.enqueue(r, false)
}

// handleEnqueueAll enqueues multiple modules for all govulncheck modes.
func (h *GovulncheckServer) handleEnqueueAll(w http.ResponseWriter, r *http.Request) error {
	return h.enqueue(r, true)
}

func (h *GovulncheckServer) enqueue(r *http.Request, allModes bool) error {
	ctx := r.Context()
	params := &govulncheck.EnqueueQueryParams{Min: defaultMinImportedByCount}
	if err := scan.ParseParams(r, params); err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	modes, err := listModes(params.Mode, allModes)
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	tasks, err := createGovulncheckQueueTasks(ctx, h.cfg, params, modes)
	if err != nil {
		return err
	}
	return enqueueTasks(ctx, tasks, h.queue,
		&queue.Options{Namespace: "govulncheck", TaskNameSuffix: params.Suffix})
}

// listModes lists all applicable modes depending on who called it. If enqueue did (allModes=false),
// returns only valid modeParam. If enqueueAll did (allModes=true), returns modes that enqueueAll
// supports, which are modes/{ModeCompare}.
func listModes(modeParam string, allModes bool) ([]string, error) {
	if allModes {
		if modeParam != "" {
			return nil, errors.New("mode query param provided for enqueueAll")
		}
		var ms []string
		for k := range modes {
			// Don't add ModeCompare to enqueueAll (it's something we only want to run occasionally)
			if k != ModeCompare {
				ms = append(ms, k)
			}
		}
		sort.Strings(ms) // make deterministic for testing
		return ms, nil
	}
	mode, err := govulncheckMode(modeParam)
	if err != nil {
		return nil, err
	}
	return []string{mode}, nil
}

func createGovulncheckQueueTasks(ctx context.Context, cfg *config.Config, params *govulncheck.EnqueueQueryParams, modes []string) (_ []queue.Task, err error) {
	defer derrors.Wrap(&err, "createGovulncheckQueueTasks(%v)", modes)
	var (
		tasks    []queue.Task
		modspecs []scan.ModuleSpec
	)
	for _, mode := range modes {
		if modspecs == nil {
			modspecs, err = readModules(ctx, cfg, params.File, params.Min)
			if err != nil {
				return nil, err
			}
		}
		reqs := moduleSpecsToGovulncheckScanRequests(modspecs, mode)
		for _, req := range reqs {
			if req.Module != "std" { // ignore the standard library
				tasks = append(tasks, req)
			}
		}
	}
	return tasks, nil
}

func moduleSpecsToGovulncheckScanRequests(modspecs []scan.ModuleSpec, mode string) []*govulncheck.Request {
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

func govulncheckMode(mode string) (string, error) {
	if mode == "" {
		// ModeGovulncheck is the default mode.
		return ModeGovulncheck, nil
	}
	mode = strings.ToUpper(mode)
	if _, ok := modes[mode]; !ok {
		return "", fmt.Errorf("unsupported mode: %v", mode)
	}
	return mode, nil
}
