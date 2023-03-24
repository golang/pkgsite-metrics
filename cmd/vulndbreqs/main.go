// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO(jba): delete when the worker is reliably computing
// request counts.

// Command vulndbreqs inserts and displays vuln DB request counts.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/vulndbreqs"
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage:")
		fmt.Fprintln(out, "vulndbreqs add")
		fmt.Fprintln(out, "  calculate missing vuln DB counts and add to BigQuery")
		fmt.Fprintln(out, "vulndbreqs show")
		fmt.Fprintln(out, "  display vuln DB counts")
		flag.PrintDefaults()
	}

	flag.Parse()
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.Init(ctx)
	if err != nil {
		return err
	}

	client, err := bigquery.NewClientCreate(ctx, cfg.ProjectID, vulndbreqs.DatasetName)
	if err != nil {
		return err
	}
	defer client.Close()

	switch flag.Arg(0) {
	case "add":
		err = doAdd(ctx, cfg.VulnDBBucketProjectID, client)
	case "show":
		err = doShow(ctx, client)
	default:
		return fmt.Errorf("unknown command %q", flag.Arg(0))
	}
	return err
}

func doAdd(ctx context.Context, projectID string, client *bigquery.Client) error {
	return vulndbreqs.ComputeAndStore(ctx, projectID, client)
}

func doShow(ctx context.Context, client *bigquery.Client) error {
	counts, err := vulndbreqs.ReadFromBigQuery(ctx, client)
	if err != nil {
		return err
	}
	for _, c := range counts {
		fmt.Printf("%s\t%d\n", c.Date, c.Count)
	}
	return nil
}
