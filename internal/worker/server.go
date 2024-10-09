// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package worker provides functionality for running a worker service.
package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cloud.google.com/go/errorreporting"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/fstore"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/jobs"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/observe"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/queue"
)

type Server struct {
	cfg         *config.Config
	observer    *observe.Observer
	bqClient    *bigquery.Client
	proxyClient *proxy.Client
	queue       queue.Queue
	jobDB       *jobs.DB
	// Firestore namespace for storing work versions.
	fsNamespace *fstore.Namespace

	// reqs is the number of incoming scan requests, both analysis and
	// govulncheck. Used for monitoring, debugging, and server restart.
	reqs atomic.Uint64

	devMode bool
	mu      sync.Mutex
}

// Info summarizes Server execution as text.
func (s *Server) Info() string {
	return fmt.Sprintf("total requests: %d", s.reqs.Load())
}

func NewServer(ctx context.Context, cfg *config.Config) (_ *Server, err error) {
	defer derrors.WrapAndReport(&err, "NewServer")

	var bq *bigquery.Client
	if strings.EqualFold(cfg.BigQueryDataset, "disable") {
		log.Infof(ctx, "BigQuery disabled")
	} else {
		bq, err = bigquery.NewClientCreate(ctx, cfg.ProjectID, cfg.BigQueryDataset)
		if err != nil {
			return nil, err
		}
	}

	// Use the same name for the namespace as the BQ dataset.
	ns, err := fstore.OpenNamespace(ctx, cfg.ProjectID, cfg.BigQueryDataset)
	if err != nil {
		return nil, err
	}

	q, err := queue.New(ctx, cfg,
		func(ctx context.Context, t queue.Task) (int, error) {
			// When running locally, only the module path and version are
			// printed for now.
			log.Infof(ctx, "enqueuing %s?%s", t.Path(), t.Params())
			return 0, nil
		})
	log.Debugf(ctx, "queue.New returned err %v", err)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	proxyClient, err := proxy.New(cfg.ProxyURL)
	log.Debugf(ctx, "proxy.New returned err %v", err)
	if err != nil {
		return nil, err
	}

	var jdb *jobs.DB
	if cfg.ProjectID != "" {
		var err error
		jdb, err = jobs.NewDB(ctx, cfg.ProjectID, cfg.BigQueryDataset)
		if err != nil {
			return nil, err
		}
	}
	s := &Server{
		cfg:         cfg,
		bqClient:    bq,
		queue:       q,
		proxyClient: proxyClient,
		devMode:     cfg.DevMode,
		jobDB:       jdb,
		fsNamespace: ns,
	}

	if cfg.ProjectID != "" && cfg.ServiceID != "" {
		s.observer, err = observe.NewObserver(ctx, cfg.ProjectID, cfg.ServiceID)
		log.Debugf(ctx, "observe.NewObserver returned err %v", err)
		if err != nil {
			return nil, err

		}
	}
	if cfg.UseErrorReporting {
		reportingClient, err := errorreporting.NewClient(ctx, cfg.ProjectID, errorreporting.Config{
			ServiceName: cfg.ServiceID,
			OnError: func(err error) {
				log.Errorf(ctx, err, "error-reporting failed")
			},
		})
		log.Debugf(ctx, "errorreporting.NewClient returned err %v", err)
		if err != nil {
			return nil, err
		}
		derrors.SetReportingClient(reportingClient)
	}

	if err := ensureTable(ctx, bq, govulncheck.TableName); err != nil {
		return nil, err
	}
	s.registerGovulncheckHandlers()
	if err := ensureTable(ctx, bq, analysis.TableName); err != nil {
		return nil, err
	}
	if err := s.registerAnalysisHandlers(ctx); err != nil {
		return nil, err
	}

	// compute vulndb entries
	s.handle("/vulndb", s.handleVulnDB)
	// compute missing vuln.go.dev request counts
	s.handle("/compute-requests", s.handleComputeRequests)
	s.handle("/jobs/", s.handleJobs)
	return s, nil
}

func ensureTable(ctx context.Context, bq *bigquery.Client, name string) error {
	if bq == nil {
		return nil
	}
	created, err := bq.CreateOrUpdateTable(ctx, name)
	if err != nil {
		return err
	}
	verb := "updated"
	if created {
		verb = "created"
	}
	log.Infof(ctx, "%s table %s\n", verb, name)
	return nil
}

const metricNamespace = "ecosystem/worker"

type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func (s *Server) handle(pattern string, handler handlerFunc) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		logger := log.FromContext(ctx)
		if t := r.Header.Get("X-Cloud-Trace-Context"); t != "" {
			logger = logger.With("traceID", t)
		}
		ctx = log.NewContext(ctx, logger)
		r = r.WithContext(ctx)

		// For logging, construct a string with the entire URL except scheme and host.
		url2 := *r.URL
		url2.Scheme = ""
		url2.Host = ""
		urlString := url2.String()

		log.Infof(ctx, "starting %s", urlString)
		w2 := &responseWriter{ResponseWriter: w}
		if err := handler(w2, r); err != nil {
			derrors.Report(err)
			s.serveError(ctx, w2, r, err)
		}
		logger.Info(fmt.Sprintf("ending %s", urlString),
			"latency", time.Since(start),
			"status", translateStatus(w2.status))
	})
	http.Handle(pattern, s.observer.Observe(h))
}

func (s *Server) registerGovulncheckHandlers() {
	h := newGovulncheckServer(s)
	s.handle("/govulncheck/enqueueall", h.handleEnqueueAll)
	s.handle("/govulncheck/enqueue", h.handleEnqueue)
	s.handle("/govulncheck/scan/", reqMonitorHandler(s, h.handleScan))
}

func (s *Server) registerAnalysisHandlers(ctx context.Context) error {
	h, err := newAnalysisServer(ctx, s)
	if err != nil {
		return err
	}
	s.handle("/analysis/scan/", reqMonitorHandler(s, h.handleScan))
	s.handle("/analysis/enqueue", h.handleEnqueue)
	return nil
}

// reqMonitorHandler creates a handler with h that 1) updates server request statistics
// and 2) resets the server after a certain number of incoming server requests. The
// incoming request that triggers the reset will be disregarded. Cloud Run will retry
// that request.
func reqMonitorHandler(s *Server, h func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	const reqLimit = 250 // experimentally shown to be a good threshold
	return func(w http.ResponseWriter, r *http.Request) error {
		// Reset the server after a certain number of requests due to a process leak.
		// TODO(#65215): why does this happen? It seems to be due to gvisor.
		if s.reqs.Load() > reqLimit {
			log.Infof(r.Context(), "resetting server after %d requests, just before: %v", reqLimit, r.URL.Path)
			os.Exit(0)
		}
		s.reqs.Add(1)
		return h(w, r)
	}
}

type serverError struct {
	status int   // HTTP status code
	err    error // wrapped error
}

func (s *serverError) Error() string {
	return fmt.Sprintf("%d (%s): %v", s.status, http.StatusText(s.status), s.err)
}

func (s *Server) serveError(ctx context.Context, w http.ResponseWriter, _ *http.Request, err error) {
	if errors.Is(err, derrors.InvalidArgument) {
		err = &serverError{err: err, status: http.StatusBadRequest}
	}
	if errors.Is(err, derrors.NotFound) {
		err = &serverError{err: err, status: http.StatusNotFound}
	}
	if errors.Is(err, derrors.BadModule) {
		err = &serverError{err: err, status: http.StatusNotAcceptable}
	}
	serr, ok := err.(*serverError)
	if !ok {
		serr = &serverError{status: http.StatusInternalServerError, err: err}
	}
	if serr.status == http.StatusInternalServerError {
		log.Errorf(ctx, err, "internal server error")
	} else {
		log.Warnf(ctx, "returning %v", err)
	}
	http.Error(w, serr.err.Error(), serr.status)
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func translateStatus(code int) int64 {
	if code == 0 {
		return http.StatusOK
	}
	return int64(code)
}

var locNewYork *time.Location

func init() {
	var err error
	locNewYork, err = time.LoadLocation("America/New_York")
	if err != nil {
		log.Errorf(context.Background(), err, "time.LoadLocation")
		os.Exit(1)
	}
}

func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(locNewYork).Format("2006-01-02 15:04:05")
}
