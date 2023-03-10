// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package observe provides metric and tracing support for Go servers.
// It uses OpenTelemetry and the golang.org/x/exp/events package.
package observe

import (
	"context"
	"net/http"

	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/derrors"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	gcppropagator "github.com/GoogleCloudPlatform/opentelemetry-operations-go/propagator"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	eotel "golang.org/x/exp/event/otel"
)

// An Observer handles tracing and metrics exporting.
type Observer struct {
	ctx            context.Context
	tracerProvider *sdktrace.TracerProvider
	traceHandler   *eotel.TraceHandler
	metricHandler  *eotel.MetricHandler
	propagator     propagation.TextMapPropagator
}

// NewObserver creates an Observer.
// The context is used to flush traces in AfterRequest, so it should be longer-lived
// than any request context.
// (We don't want to use the request context because we still want traces even if
// it is canceled or times out.)
func NewObserver(ctx context.Context, projectID, serverName string) (_ *Observer, err error) {
	defer derrors.Wrap(&err, "NewObserver(%q, %q)", projectID, serverName)

	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		return nil, err
	}
	// Create exporter (collector embedded with the exporter).
	controller, err := mexporter.NewExportPipeline([]mexporter.Option{
		mexporter.WithProjectID(projectID),
	})
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		// Enable tracing if there is no incoming request, or if the incoming
		// request is sampled.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithBatcher(exporter))
	return &Observer{
		ctx:            ctx,
		tracerProvider: tp,
		traceHandler:   eotel.NewTraceHandler(tp.Tracer(serverName)),
		metricHandler:  eotel.NewMetricHandler(controller.Meter(serverName)),
		// The propagator extracts incoming trace IDs so that we can connect our trace spans
		// to the incoming ones constructed by Cloud Run.
		propagator: propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
			gcppropagator.New()),
	}, nil
}

// Observe adds metrics and tracing to an http.Handler.
func (o *Observer) Observe(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o == nil {
			h.ServeHTTP(w, r.WithContext(r.Context()))
			return
		}
		exporter := event.NewExporter(o, nil)
		ctx := event.WithExporter(r.Context(), exporter)
		ctx = o.propagator.Extract(ctx, propagation.HeaderCarrier(r.Header))
		defer o.tracerProvider.ForceFlush(o.ctx)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Event implements event.Handler.
func (o *Observer) Event(ctx context.Context, ev *event.Event) context.Context {
	ctx = o.traceHandler.Event(ctx, ev)
	return o.metricHandler.Event(ctx, ev)
}
