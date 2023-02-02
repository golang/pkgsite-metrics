// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/errorreporting"
	"github.com/google/safehtml/template"
	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/observe"
	"golang.org/x/pkgsite-metrics/internal/proxy"
)

type Server struct {
	cfg         *config.Config
	observer    *observe.Observer
	bqClient    *bigquery.Client
	proxyClient *proxy.Client
	staticPath  template.TrustedSource

	devMode   bool
	mu        sync.Mutex
	templates map[string]*template.Template
}

var errBQDisabled = &serverError{http.StatusPreconditionRequired, errors.New("BigQuery disabled on this server")}

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
		for _, tableID := range bigquery.Tables() {
			created, err := bq.CreateOrUpdateTable(ctx, tableID)
			if err != nil {
				return nil, err
			}
			verb := "updated"
			if created {
				verb = "created"
			}
			log.Infof(ctx, "%s table %s\n", verb, tableID)
		}
	}

	proxyClient, err := proxy.New(cfg.ProxyURL)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:         cfg,
		bqClient:    bq,
		proxyClient: proxyClient,
		devMode:     cfg.DevMode,
		staticPath:  cfg.StaticPath,
	}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}

	s.observer, err = observe.NewObserver(ctx, cfg.ProjectID, "go-metrics-worker")
	if err != nil {
		return nil, err
	}
	// This function will be called for each request.
	// It lets us install a log handler that knows about the request's
	// trace ID.
	s.observer.LogHandlerFunc = func(r *http.Request) event.Handler {
		traceID := r.Header.Get("X-Cloud-Trace-Context")
		return log.NewGCPJSONHandler(os.Stderr, traceID)
	}

	if cfg.UseErrorReporting {
		reportingClient, err := errorreporting.NewClient(ctx, cfg.ProjectID, errorreporting.Config{
			ServiceName: cfg.ServiceID,
			OnError: func(err error) {
				log.Errorf(ctx, "Error reporting failed: %v", err)
			},
		})
		if err != nil {
			return nil, err
		}
		derrors.SetReportingClient(reportingClient)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(s.staticPath.String()))))

	s.handle("/favicon.ico", func(w http.ResponseWriter, r *http.Request) error {
		http.ServeFile(w, r, filepath.Join(s.staticPath.String(), "favicon.ico"))
		return nil
	})
	s.handle("/", s.handleIndexPage)
	return s, nil
}

const metricNamespace = "ecosystem/worker"

type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func (s *Server) handle(pattern string, handler handlerFunc) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		log.With("httpRequest", r).Infof(ctx, "starting %s", r.URL.Path)

		w2 := &responseWriter{ResponseWriter: w}
		if err := handler(w2, r); err != nil {
			log.Errorf(ctx, err.Error())
			derrors.Report(err)
			s.serveError(ctx, w2, r, err)
		}
		log.With(
			"latency", time.Since(start),
			"status", translateStatus(w2.status)).
			Infof(ctx, "request end")
	})
	http.Handle(pattern, s.observer.Observe(h))
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
		log.Errorf(ctx, serr.err.Error())
	} else {
		log.Warningf(ctx, "returning %v", err)
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
		log.Errorf(context.Background(), "time.LoadLocation: %v", err)
		os.Exit(1)
	}
}

func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(locNewYork).Format("2006-01-02 15:04:05")
}
