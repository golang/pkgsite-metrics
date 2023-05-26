// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command jobs supports jobs on ecosystem-metrics.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"text/tabwriter"
	"time"

	credsapi "cloud.google.com/go/iam/credentials/apiv1"
	credspb "cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"golang.org/x/pkgsite-metrics/internal/jobs"
)

var env = flag.String("env", "prod", "worker environment (dev or prod)")

var commands = []command{
	{"print-identity-token", "",
		"print an identity token", doPrintToken},
	{"list", "",
		"list jobs", doList},
	{"show", "jobID...",
		"display information about jobs", doShow},
	{"cancel", "jobID...",
		"cancel the jobs", doCancel},
}

type command struct {
	name   string
	argdoc string
	desc   string
	run    func(context.Context, []string) error
}

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage:")
		for _, cmd := range commands {
			fmt.Fprintf(out, "  job %s %s\n", cmd.name, cmd.argdoc)
			fmt.Fprintf(out, "\t%s\n", cmd.desc)
		}
		fmt.Fprintln(out, "\ncommon flags:")
		flag.PrintDefaults()
	}

	flag.Parse()
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		flag.Usage()
		os.Exit(2)
	}
}

var workerURL string

func run(ctx context.Context) error {
	wu := os.Getenv("GO_ECOSYSTEM_WORKER_URL_SUFFIX")
	if wu == "" {
		return errors.New("need GO_ECOSYSTEM_WORKER_URL_SUFFIX environment variable")
	}
	workerURL = fmt.Sprintf("https://%s-%s", *env, wu)
	name := flag.Arg(0)
	for _, cmd := range commands {
		if cmd.name == name {
			return cmd.run(ctx, flag.Args()[1:])
		}
	}
	return fmt.Errorf("unknown command %q", name)
}

func doShow(ctx context.Context, args []string) error {
	token, err := requestImpersonateIdentityToken(ctx)
	if err != nil {
		return err
	}
	for _, jobID := range args {
		if err := showJob(ctx, jobID, token); err != nil {
			return err
		}
	}
	return nil
}

func showJob(ctx context.Context, jobID, token string) error {
	job, err := requestJSON[jobs.Job](ctx, "jobs/describe?jobid="+jobID, token)
	if err != nil {
		return err
	}
	rj := reflect.ValueOf(job).Elem()
	rt := rj.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.IsExported() {
			v := rj.FieldByIndex(f.Index)
			fmt.Printf("%s: %v\n", f.Name, v.Interface())
		}
	}
	return nil
}

func doList(ctx context.Context, _ []string) error {
	token, err := requestImpersonateIdentityToken(ctx)
	if err != nil {
		return err
	}
	joblist, err := requestJSON[[]jobs.Job](ctx, "jobs/list", token)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 2, 8, 1, ' ', 0)
	fmt.Fprintf(tw, "ID\tUser\tStart Time\tStarted\tFinished\tTotal\tCanceled\n")
	for _, j := range *joblist {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%t\n",
			j.ID(), j.User, j.StartedAt.Format(time.RFC3339),
			j.NumStarted,
			j.NumSkipped+j.NumFailed+j.NumErrored+j.NumSucceeded,
			j.NumEnqueued,
			j.Canceled)
	}
	return tw.Flush()
}

func doCancel(ctx context.Context, args []string) error {
	token, err := requestImpersonateIdentityToken(ctx)
	if err != nil {
		return err
	}
	for _, jobID := range args {
		if _, err := httpGet(ctx, workerURL+"/jobs/cancel?jobid="+jobID, token); err != nil {
			return fmt.Errorf("canceling %q: %w", jobID, err)
		}
	}
	return nil
}

// For testing. Can be used in place of `gcloud auth print-identity-token`.
func doPrintToken(ctx context.Context, _ []string) error {
	token, err := requestImpersonateIdentityToken(ctx)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// requestJSON requests the path from the worker, then reads the returned body
// and unmarshals it as JSON.
func requestJSON[T any](ctx context.Context, path, token string) (*T, error) {
	body, err := httpGet(ctx, workerURL+"/"+path, token)
	if err != nil {
		return nil, err
	}
	var t T
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// httpGet makes a GET request to the given URL with the given identity token.
// It reads the body and returns the HTTP response and the body.
func httpGet(ctx context.Context, url, token string) (body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body (%s): %v", res.Status, err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", res.Status, body)
	}
	return body, nil
}

// requestImpersonateIdentityToken requests an identity token for a service
// account to impersonate from the iamcredentials service.
// See https://cloud.google.com/iam/docs/reference/credentials/rest.
func requestImpersonateIdentityToken(ctx context.Context) (string, error) {
	c, err := credsapi.NewIamCredentialsClient(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	serviceAccountEmail := "impersonate@go-ecosystem.iam.gserviceaccount.com"
	req := &credspb.GenerateIdTokenRequest{
		Name:         "projects/-/serviceAccounts/" + serviceAccountEmail,
		Audience:     workerURL,
		IncludeEmail: true,
	}
	res, err := c.GenerateIdToken(ctx, req)
	if err != nil {
		return "", fmt.Errorf("GenerateIdToken: %w", err)
	}
	return res.Token, nil
}
