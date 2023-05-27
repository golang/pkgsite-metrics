// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command jobs supports jobs on ecosystem-metrics.
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"text/tabwriter"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"golang.org/x/pkgsite-metrics/internal/jobs"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

const projectID = "go-ecosystem"

var env = flag.String("env", "prod", "worker environment (dev or prod)")

var commands = []command{
	{"list", "",
		"list jobs", doList},
	{"show", "JOBID...",
		"display information about jobs", doShow},
	{"cancel", "JOBID...",
		"cancel the jobs", doCancel},
	{"start", "BINARY [MIN_IMPORTERS]",
		"start a job", doStart},
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
	ts, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	for _, jobID := range args {
		if err := showJob(ctx, jobID, ts); err != nil {
			return err
		}
	}
	return nil
}

func showJob(ctx context.Context, jobID string, ts oauth2.TokenSource) error {
	job, err := requestJSON[jobs.Job](ctx, "jobs/describe?jobid="+jobID, ts)
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
	ts, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	joblist, err := requestJSON[[]jobs.Job](ctx, "jobs/list", ts)
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
	ts, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	for _, jobID := range args {
		if _, err := httpGet(ctx, workerURL+"/jobs/cancel?jobid="+jobID, ts); err != nil {
			return fmt.Errorf("canceling %q: %w", jobID, err)
		}
	}
	return nil
}

func doStart(ctx context.Context, args []string) error {
	// Validate arguments.
	if len(args) < 1 || len(args) > 2 {
		return errors.New("wrong number of args: want BINARY [MIN_IMPORTERS]")
	}
	min := -1
	if len(args) > 1 {
		m, err := strconv.Atoi(args[1])
		if err != nil {
			return err
		}
		if m < 0 {
			return errors.New("MIN_IMPORTERS cannot be negative")
		}
		min = m
	}
	binaryFile := args[0]
	if fi, err := os.Stat(binaryFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s does not exist", binaryFile)
		}
		return err
	} else if fi.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", binaryFile)
	}

	// Copy binary to GCS if it's not already there.
	if err := uploadAnalysisBinary(ctx, binaryFile); err != nil {
		return err
	}

	// Ask the server to enqueue scan tasks.
	its, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/analysis/enqueue?binary=%s&user=%s", workerURL, filepath.Base(binaryFile), os.Getenv("USER"))
	if min >= 0 {
		url += fmt.Sprintf("&min=%d", min)
	}
	body, err := httpGet(ctx, url, its)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", body)
	return nil
}

// uploadAnalysisBinary copies binaryFile to the GCS location used for
// analysis binaries.
// As an optimization, it skips the upload if the file is already on GCS
// and has the same checksum as the local file.
func uploadAnalysisBinary(ctx context.Context, binaryFile string) error {
	const bucketName = projectID
	binaryName := filepath.Base(binaryFile)
	objectName := path.Join("analysis-binaries", binaryName)

	ts, err := accessTokenSource(ctx)
	if err != nil {
		return err
	}
	c, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		return err
	}
	defer c.Close()
	bucket := c.Bucket(bucketName)
	object := bucket.Object(objectName)
	attrs, err := object.Attrs(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		fmt.Printf("%s does not exist, uploading\n", object.ObjectName())
	} else if err != nil {
		return err
	} else if g, w := len(attrs.MD5), md5.Size; g != w {
		return fmt.Errorf("len(attrs.MD5) = %d, wanted %d", g, w)
	} else {
		localMD5, err := fileMD5(binaryFile)
		if err != nil {
			return err
		}
		if bytes.Equal(localMD5, attrs.MD5) {
			fmt.Printf("%s already on GCS with same checksum; not uploading\n", binaryFile)
			return nil
		} else {
			fmt.Printf("binary %s exists on GCS but hashes don't match; uploading\n", binaryName)
		}
	}
	fmt.Printf("copying %s to %s\n", binaryFile, object.ObjectName())
	return copyToGCS(ctx, object, binaryFile)
}

// fileMD5 computes the MD5 checksum of the given file.
func fileMD5(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, f); err != nil {
		return nil, err
	}
	return hash.Sum(nil)[:], nil
}

// copyToLocalFile copies the filename to the GCS object.
func copyToGCS(ctx context.Context, object *storage.ObjectHandle, filename string) error {
	src, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer src.Close()
	dest := object.NewWriter(ctx)
	if _, err := io.Copy(dest, src); err != nil {
		return err
	}
	return dest.Close()
}

// requestJSON requests the path from the worker, then reads the returned body
// and unmarshals it as JSON.
func requestJSON[T any](ctx context.Context, path string, ts oauth2.TokenSource) (*T, error) {
	body, err := httpGet(ctx, workerURL+"/"+path, ts)
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
func httpGet(ctx context.Context, url string, ts oauth2.TokenSource) (body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	token, err := ts.Token()
	if err != nil {
		return nil, err
	}
	token.SetAuthHeader(req)
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

var serviceAccountEmail = fmt.Sprintf("impersonate@%s.iam.gserviceaccount.com", projectID)

func accessTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	return impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: serviceAccountEmail,
		Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
}

func identityTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	return impersonate.IDTokenSource(ctx, impersonate.IDTokenConfig{
		TargetPrincipal: serviceAccountEmail,
		Audience:        workerURL,
		IncludeEmail:    true,
	})
}
