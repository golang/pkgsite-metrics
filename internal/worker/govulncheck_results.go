// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/civil"
	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

var insertResultsCounter = event.NewCounter("insert-results", &event.MetricOptions{Namespace: metricNamespace})

func (h *GovulncheckServer) handleInsertResults(w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		insertResultsCounter.Record(r.Context(), 1, event.Bool("success", err == nil))
	}()

	if h.bqClient == nil {
		return errBQDisabled
	}

	var date civil.Date
	if d := r.FormValue("date"); d != "" {
		var err error
		date, err = civil.ParseDate(d)
		if err != nil {
			return fmt.Errorf("%w: parsing 'date' query param: %v", derrors.InvalidArgument, err)
		}
	} else {
		date = civil.DateOf(time.Now())
	}
	allowDuplicates, err := scan.ParseOptionalBoolParam(r, "allow-dups", false)
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	ctx := r.Context()
	log.Infof(ctx, "reading results")
	results, err := govulncheck.FetchResults(ctx, h.bqClient)
	if err != nil {
		return err
	}
	log.Infof(ctx, "inserting %d results for %s", len(results), date)
	if err := govulncheck.InsertResults(ctx, h.bqClient, results, date, allowDuplicates); err != nil {
		return err
	}
	fmt.Fprintf(w, "%d results for %s inserted successfully.\n", len(results), date)
	return nil
}
