// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command worker runs the go-metrics worker server.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/exp/slog"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/worker"
)

var (
	workers  = flag.Int("workers", 10, "number of concurrent requests to the fetch service, when running locally")
	devMode  = flag.Bool("dev", false, "enable developer mode (reload templates on each page load, serve non-minified JS/CSS, etc.)")
	port     = flag.String("port", config.GetEnv("PORT", "8080"), "port to listen to")
	dataset  = flag.String("dataset", "", "dataset (overrides GO_ECOSYSTEM_BIGQUERY_DATASET env var); use 'disable' for no BQ")
	insecure = flag.Bool("insecure", false, "bypass sandbox in order to compare with old code")
	// flag used in call to safehtml/template.TrustedSourceFromFlag
	_ = flag.String("static", "static", "path to folder containing static files served")
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage:")
		fmt.Fprintln(out, "worker FLAGS")
		fmt.Fprintln(out, "  run as a server, listening at the PORT env var")
		flag.PrintDefaults()
	}

	flag.Parse()
	ctx := context.Background()
	var h slog.Handler
	if config.OnCloudRun() || *devMode {
		h = log.NewGoogleCloudHandler()
	} else {
		h = log.NewLineHandler(os.Stderr)
	}
	slog.SetDefault(slog.New(h))
	if err := runServer(ctx); err != nil {
		log.Error(ctx, "fail", err)
		os.Exit(1)
	}
}

func runServer(ctx context.Context) error {
	cfg, err := config.Init(ctx)
	if err != nil {
		return err
	}
	cfg.LocalQueueWorkers = *workers
	cfg.DevMode = *devMode
	if *dataset != "" {
		cfg.BigQueryDataset = *dataset
	}
	cfg.Insecure = *insecure
	cfg.Dump(os.Stdout)
	log.Infof(ctx, "config: project=%s, dataset=%s", cfg.ProjectID, cfg.BigQueryDataset)
	if _, err := worker.NewServer(ctx, cfg); err != nil {
		return err
	}
	addr := ":" + *port
	log.Infof(ctx, "Listening on addr http://localhost%s", addr)
	return fmt.Errorf("listening: %v", http.ListenAndServe(addr, nil))
}
