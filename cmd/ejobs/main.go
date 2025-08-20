// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command ejobs supports jobs on ecosystem-metrics.
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/jobs"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

const (
	projectID           = "go-ecosystem"
	uploaderMetadataKey = "uploader"
)

// Common flags
var (
	env    = flag.String("env", "prod", "worker environment (dev or prod)")
	dryRun = flag.Bool("n", false, "print actions but do not execute them")
)

var (
	minImporters int           // for start
	maxImporters int           // for start
	noDeps       bool          // for start
	moduleFile   string        // for start
	waitInterval time.Duration // for wait
	force        bool          // for results
	errs         bool          // for results
	outfile      string        // for results
	userFilter   string        // for list
)

var commands = []command{
	{"list", "[-user USERNAME]",
		"list jobs",
		doList,
		func(fs *flag.FlagSet) {
			fs.StringVar(&userFilter, "user", "", "filter jobs by user")
		},
	},
	{"show", "JOBID...",
		"display information about jobs in the last 7 days",
		doShow, nil},
	{"cancel", "JOBID...",
		"cancel the jobs",
		doCancel, nil},
	{"start", "[-min MIN_IMPORTERS] [-file MODULE_FILE] [-nodeps] BINARY ARGS...",
		"start a job",
		doStart,
		func(fs *flag.FlagSet) {
			fs.IntVar(&minImporters, "min", -1,
				"run on modules with at least this many importers (<0: use server default of 10)")
			fs.IntVar(&maxImporters, "max", -1,
				"run on modules with at most this many importers (<0: use server default of unlimited)")
			fs.StringVar(&moduleFile, "file", "",
				"file with modules to use: each line is MODULE_PATH VERSION NUM_IMPORTERS")
			fs.BoolVar(&noDeps, "nodeps", false, "do not download dependencies for modules")
		},
	},
	{"wait", "JOBID",
		"do not exit until JOBID is done",
		doWait,
		func(fs *flag.FlagSet) {
			fs.DurationVar(&waitInterval, "i", 0, "display updates at this interval")
		},
	},
	{"results", "[-f] [-e] [-o FILE.json] JOBID",
		"download results as JSON",
		doResults,
		func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "f", false, "download even if unfinished")
			fs.BoolVar(&errs, "e", false, "also download error results (by default, only non-error results are downloaded)")
			fs.StringVar(&outfile, "o", "", "output filename")
		},
	},
}

type command struct {
	name     string
	argdoc   string
	desc     string
	run      func(context.Context, []string) error
	flagdefs func(*flag.FlagSet)
}

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "Usage:")
		for _, cmd := range commands {
			fmt.Println()
			fmt.Fprintf(out, "ejobs %s %s\n", cmd.name, cmd.argdoc)
			fmt.Fprintf(out, "\t%s\n", cmd.desc)
			if cmd.flagdefs != nil {
				fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
				cmd.flagdefs(fs)
				fs.Usage()
			}
		}
		fmt.Fprintln(out, "\ncommon flags:")
		flag.PrintDefaults()
	}

	flag.Parse()
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n\n", err)
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
			args := flag.Args()[1:]
			if cmd.flagdefs != nil {
				fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
				cmd.flagdefs(fs)
				if err := fs.Parse(args); err != nil {
					return err
				}
				args = fs.Args()
			}
			return cmd.run(ctx, args)
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
	if *dryRun {
		return nil
	}
	rj := reflect.ValueOf(job).Elem()
	rt := rj.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.IsExported() {
			v := rj.FieldByIndex(f.Index)
			name, _ := strings.CutPrefix(f.Name, "Num")
			fmt.Printf("%s: %v\n", name, v.Interface())
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
	if *dryRun {
		return nil
	}
	d7 := -time.Hour * 24 * 7
	weekBefore := time.Now().Add(d7)
	tw := tabwriter.NewWriter(os.Stdout, 2, 8, 1, ' ', 0)
	fmt.Fprintf(tw, "ID\tUser\tStart Time\tStarted\tFinished\tTotal\tCanceled\tEstimated Time Left\n")
	for _, j := range *joblist {
		if userFilter != "" && j.User != userFilter {
			continue
		}
		if j.StartedAt.After(weekBefore) {
			done := j.NumFinished()
			etaLabel := func(d time.Duration) string {
				if d >= 0 {
					return d.String()
				}
				return "Done"
			}
			var eta time.Duration
			if !(done >= j.NumEnqueued || j.Canceled) {
				elapsed := time.Since(j.StartedAt)
				rate := float64(done) / elapsed.Seconds()
				remainingTasks := float64(j.NumEnqueued - done)
				eta = time.Duration(remainingTasks / rate * float64(time.Second)).Round(time.Minute)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%t\t%s\n",
				j.ID(), j.User, j.StartedAt.Format(time.RFC3339),
				j.NumStarted,
				j.NumSkipped+j.NumFailed+j.NumErrored+j.NumSucceeded,
				j.NumEnqueued,
				j.Canceled,
				etaLabel(eta))
		}
	}
	return tw.Flush()
}

func doCancel(ctx context.Context, args []string) error {
	ts, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	for _, jobID := range args {
		url := workerURL + "/jobs/cancel?jobid=" + jobID
		if *dryRun {
			fmt.Printf("dryrun: GET %s\n", url)
			continue
		}
		if _, err := httpGet(ctx, url, ts); err != nil {
			return fmt.Errorf("canceling %q: %w", jobID, err)
		}
	}
	return nil
}

func doWait(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("wrong number of args: want [-i DURATION] JOB_ID")
	}
	jobID := args[0]
	sleepInterval := waitInterval
	displayUpdates := sleepInterval != 0
	if sleepInterval < time.Second {
		sleepInterval = time.Second
	}
	ts, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	start := time.Now()
	var jobStartedAt time.Time
	for {
		job, err := requestJSON[jobs.Job](ctx, "jobs/describe?jobid="+jobID, ts)
		if err != nil {
			return err
		}
		jobStartedAt = job.StartedAt
		done := job.NumFinished()
		if done >= job.NumEnqueued {
			break
		}
		if displayUpdates {
			fmt.Printf("%s: %d/%d completed (%d%%)\n",
				time.Since(start).Round(time.Second), done, job.NumEnqueued, done*100/job.NumEnqueued)
		}
		time.Sleep(sleepInterval)
	}
	fmt.Printf("Job %s finished in %s.\n", jobID, time.Since(jobStartedAt))
	return nil
}

// GCS folders for types of files.
const (
	binaryFolder     = "analysis-binaries"
	moduleFileFolder = "module-files"
)

func doStart(ctx context.Context, args []string) error {
	user := os.Getenv("USER")

	// Validate arguments.
	if len(args) == 0 {
		return errors.New("wrong number of args: want [-min N] [-file MODULE_FILE] [-nodeps] BINARY [ARG1 ARG2 ...]")
	}
	binaryFile := args[0]
	if fi, err := os.Stat(binaryFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s does not exist", binaryFile)
		}
		return err
	} else if fi.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", binaryFile)
	} else if err := checkIsLinuxAmd64(binaryFile); err != nil {
		return err
	}
	// Check args to binary for whitespace, which we don't support.
	binaryArgs := args[1:]
	for _, arg := range binaryArgs {
		if strings.IndexFunc(arg, unicode.IsSpace) >= 0 {
			return fmt.Errorf("arg %q contains whitespace: not supported", arg)
		}
	}

	// Copy binary to GCS if it's not already there.
	if _, canceled, err := uploadFile(ctx, binaryFile, binaryFolder); err != nil {
		return err
	} else if canceled {
		return nil
	}

	// Copy file to GCS if one is given.
	modFileFolder := moduleFileFolder
	if user != "" {
		modFileFolder = path.Join(user, modFileFolder)
	}

	var gcsPath string
	if moduleFile != "" {
		var canceled bool
		var err error
		gcsPath, canceled, err = uploadFile(ctx, moduleFile, modFileFolder)
		if err != nil {
			return err
		}
		if canceled {
			return nil
		}
	}

	// Ask the server to enqueue scan tasks.
	its, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/analysis/enqueue?binary=%s&user=%s&nodeps=%t",
		workerURL, filepath.Base(binaryFile), user, noDeps)
	if len(binaryArgs) > 0 {
		u += fmt.Sprintf("&args=%s", url.QueryEscape(strings.Join(binaryArgs, " ")))
	}
	if minImporters >= 0 {
		u += fmt.Sprintf("&min=%d", minImporters)
	}
	if maxImporters >= 0 {
		u += fmt.Sprintf("&max=%d", maxImporters)
	}
	if gcsPath != "" {
		gurl := "gs://" + gcsPath
		u += fmt.Sprintf("&file=%s", url.QueryEscape(gurl))
	}
	if *dryRun {
		fmt.Printf("dryrun: GET %s\n", u)
		return nil
	}
	body, err := httpGet(ctx, u, its)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", body)
	return nil
}

// checkIsLinuxAmd64 checks if binaryFile is a linux/amd64 Go
// binary. If not, returns an error with appropriate message.
// Otherwise, returns nil.
func checkIsLinuxAmd64(binaryFile string) error {
	bin, err := os.Open(binaryFile)
	if err != nil {
		return err
	}
	defer bin.Close()

	bi, err := buildinfo.Read(bin)
	if err != nil {
		return err
	}

	var goos, goarch string
	for _, setting := range bi.Settings {
		if setting.Key == "GOOS" {
			goos = setting.Value
		} else if setting.Key == "GOARCH" {
			goarch = setting.Value
		}
	}

	if goos != "linux" || goarch != "amd64" {
		return fmt.Errorf("binary not built for linux/amd64: GOOS=%s GOARCH=%s", goos, goarch)
	}
	return nil
}

// uploadFile copies localFile to the GCS location used for files.
// The GCS bucket is the projectID, defined above.
// The name of the destination object is the join of the remoteFolder and the basename
// of the localFile. For example, file ~/things/data.txt uploaded to folder "stuff" will be written
// to the object "stuff/data.txt".
//
// The user can cancel the upload if the file with the same name is already on GCS,
// upon which true is returned. Otherwise, false is returned.
//
// As an optimization, the upload is skipped if the file on GCS has the same checksum as the local file.
func uploadFile(ctx context.Context, localFile, remoteFolder string) (gcsPath string, canceled bool, err error) {
	const bucketName = projectID
	baseName := filepath.Base(localFile)
	objectName := path.Join(remoteFolder, baseName)
	gcsPath = path.Join(bucketName, objectName)

	if *dryRun {
		fmt.Printf("dryrun: upload file %s\n", localFile)
		return gcsPath, false, nil
	}

	ts, err := accessTokenSource(ctx)
	if err != nil {
		return "", false, err
	}
	c, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		return "", false, err
	}
	defer c.Close()
	bucket := c.Bucket(bucketName)
	object := bucket.Object(objectName)
	attrs, err := object.Attrs(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		fmt.Printf("%s file does not exist on GCS: uploading\n", baseName)
	} else if err != nil {
		return "", false, err
	} else if g, w := len(attrs.MD5), md5.Size; g != w {
		return "", false, fmt.Errorf("len(attrs.MD5) = %d, wanted %d", g, w)

	} else {
		localMD5, err := fileMD5(localFile)
		if err != nil {
			return "", false, err
		}
		if bytes.Equal(localMD5, attrs.MD5) {
			fmt.Printf("File %q on GCS has the same checksum: not uploading.\n", baseName)
			return gcsPath, false, nil
		}
		// Ask the users if they want to overwrite the existing file
		// while providing more info to help them with their decision.
		updated := attrs.Updated.In(time.Local).Format(time.RFC1123) // use local time zone
		fmt.Printf("The file %q already exists on GCS.\n", baseName)
		fmt.Printf("It was last uploaded on %s", updated)
		// Communicate uploader info if available.
		if uploader := attrs.Metadata[uploaderMetadataKey]; uploader != "" {
			fmt.Printf(" by %s", uploader)
		}
		fmt.Println(".")
		fmt.Print("Do you wish to overwrite it? [y/n] ")
		var response string
		fmt.Scanln(&response)
		if r := strings.TrimSpace(response); r != "y" && r != "Y" {
			// Accept "Y" and "y" as confirmation.
			fmt.Println("Cancelling.")
			return "", true, nil
		}
	}
	fmt.Printf("Uploading.\n")
	if err := copyToGCS(ctx, object, localFile); err != nil {
		return "", false, err
	}

	// Add the uploader information for better messaging in the future.
	toUpdate := storage.ObjectAttrsToUpdate{
		Metadata: map[string]string{uploaderMetadataKey: os.Getenv("USER")},
	}
	// Refetch the object, otherwise attribute uploading won't have effect.
	object = bucket.Object(objectName)
	object.Update(ctx, toUpdate) // disregard errors
	return gcsPath, false, nil
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

func doResults(ctx context.Context, args []string) (err error) {
	if len(args) == 0 {
		return errors.New("wrong number of args: want [-f] [-e] [-o FILE.json] JOB_ID")
	}
	jobID := args[0]
	ts, err := identityTokenSource(ctx)
	if err != nil {
		return err
	}
	job, err := requestJSON[jobs.Job](ctx, "jobs/describe?jobid="+jobID, ts)
	if err != nil {
		return err
	}
	done := job.NumFinished()
	if !force && done < job.NumEnqueued {
		return fmt.Errorf("job not finished (%d/%d completed); use -f for partial results", done, job.NumEnqueued)
	}
	results, err := requestJSON[[]*analysis.Result](ctx, fmt.Sprintf("jobs/results?jobid=%s&errors=%t", jobID, errs), ts)
	if err != nil {
		return err
	}
	out := os.Stdout
	if outfile != "" {
		out, err = os.Create(outfile)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, out.Close()) }()
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "\t")
	return enc.Encode(results)
}

// requestJSON requests the path from the worker, then reads the returned body
// and unmarshals it as JSON.
func requestJSON[T any](ctx context.Context, path string, ts oauth2.TokenSource) (*T, error) {
	url := workerURL + "/" + path
	if *dryRun {
		fmt.Printf("GET %s\n", url)
		return nil, nil
	}
	body, err := httpGet(ctx, url, ts)
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
