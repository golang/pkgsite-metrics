// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO(jba): delete when the worker is reliably computing
// request counts.

// Command vulndbreqs inserts and displays vuln DB request counts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"

	"cloud.google.com/go/civil"
	"golang.org/x/pkgsite-metrics/internal"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/vulndbreqs"
)

var (
	limit    = flag.Int("limit", 0, "max log entries to compute")
	fromDate = flag.String("from", "", "start date for compute")
	toDate   = flag.String("to", "", "end date for compute")
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage:")
		fmt.Fprintln(out, "vulndbreqs add [DATE]")
		fmt.Fprintln(out, "  calculate missing vuln DB counts and add to BigQuery")
		fmt.Fprintln(out, "vulndbreqs compute")
		fmt.Fprintln(out, "  calculate and display vuln DB counts")
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
	if cfg.ProjectID == "" {
		return errors.New("missing project ID (GOOGLE_CLOUD_PROJECT environment variable)")
	}
	client, err := bigquery.NewClientCreate(ctx, cfg.ProjectID, vulndbreqs.DatasetName)
	if err != nil {
		return err
	}
	defer client.Close()

	keyName := "projects/" + cfg.ProjectID + "/secrets/vulndb-hmac-key"
	var hmacKey []byte
	if flag.Arg(0) == "add" || flag.Arg(0) == "compute" {
		hk, err := internal.GetSecret(ctx, keyName)
		if err != nil {
			return err
		}
		hmacKey = []byte(hk)
	}

	switch flag.Arg(0) {
	case "add":
		err = doAdd(ctx, cfg.VulnDBBucketProjectID, client, hmacKey, flag.Arg(1))
	case "compute":
		err = doCompute(ctx, cfg.VulnDBBucketProjectID, hmacKey)
	case "show":
		err = doShow(ctx, client)
	default:
		return fmt.Errorf("unknown command %q", flag.Arg(0))
	}
	return err
}

func doAdd(ctx context.Context, projectID string, client *bigquery.Client, hmacKey []byte, date string) error {
	if date == "" {
		return vulndbreqs.ComputeAndStore(ctx, projectID, client, hmacKey)
	}
	d, err := civil.ParseDate(date)
	if err != nil {
		return err
	}
	return vulndbreqs.ComputeAndStoreDate(ctx, projectID, client, hmacKey, d)
}

func doCompute(ctx context.Context, projectID string, hmacKey []byte) error {
	from, err := civil.ParseDate(*fromDate)
	if err != nil {
		return err
	}
	from = from.AddDays(-1)
	to, err := civil.ParseDate(*toDate)
	if err != nil {
		return err
	}
	to = to.AddDays(1)
	rcs, err := vulndbreqs.Compute(ctx, projectID, from, to, *limit, hmacKey)
	if err != nil {
		return err
	}
	for _, rc := range rcs {
		fmt.Printf("%s\t%d\t%s\n", rc.Date, rc.Count, rc.IP)
	}
	return nil
}

func doShow(ctx context.Context, client *bigquery.Client) error {
	counts, err := vulndbreqs.ReadRequestCountsFromBigQuery(ctx, client)
	if err != nil {
		return err
	}
	for _, c := range counts {
		fmt.Printf("%s\t%d\n", c.Date, c.Count)
	}
	return nil
}
