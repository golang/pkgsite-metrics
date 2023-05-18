// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/jobs"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/scan"
	"golang.org/x/pkgsite-metrics/internal/version"
)

type analysisServer struct {
	*Server
	openFile           openFileFunc // Used to open binary files from GCS, except for testing.
	storedWorkVersions map[analysis.WorkVersionKey]analysis.WorkVersion
}

func newAnalysisServer(ctx context.Context, s *Server) (*analysisServer, error) {
	if s.cfg.BinaryBucket == "" {
		return nil, errors.New("missing binary bucket (define GO_ECOSYSTEM_BINARY_BUCKET)")
	}
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	bucket := c.Bucket(s.cfg.BinaryBucket)
	var wvs map[analysis.WorkVersionKey]analysis.WorkVersion
	if s.bqClient != nil {
		wvs, err = analysis.ReadWorkVersions(ctx, s.bqClient)
		if err != nil {
			return nil, err
		}
		log.Infof(ctx, "read %d work versions", len(wvs))
	}
	return &analysisServer{
		Server:             s,
		openFile:           gcsOpenFileFunc(ctx, bucket),
		storedWorkVersions: wvs,
	}, nil
}

const analysisBinariesBucketDir = "analysis-binaries"

func (s *analysisServer) handleScan(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "analysisServer.handleScan")
	ctx := r.Context()

	req, err := analysis.ParseScanRequest(r, "/analysis/scan")
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}

	// If there is a job and it's canceled, return immediately.
	if req.JobID != "" && s.jobDB != nil {
		job, err := s.jobDB.GetJob(ctx, req.JobID)
		if err != nil {
			log.Errorf(ctx, err, "failed to get job for id %q", req.JobID)
		} else if job.Canceled {
			log.Infof(ctx, "job %q canceled; skipping", req.JobID)
			return nil
		}
	}

	// updateJob updates the job for this request if there is one.
	// If there is an error, it logs it instead of failing.
	updateJob := func(f func(*jobs.Job)) {
		if req.JobID != "" && s.jobDB != nil {
			err := s.jobDB.UpdateJob(ctx, req.JobID, func(j *jobs.Job) error {
				f(j)
				return nil
			})
			if err != nil {
				log.Errorf(ctx, err, "failed to update job for id %q", req.JobID)
			}
		}
	}

	updateJob(func(j *jobs.Job) { j.NumStarted++ })

	// Handle errors here.
	defer func() {
		if err != nil {
			updateJob(func(j *jobs.Job) { j.NumFailed++ })
		}
	}()

	if req.Suffix != "" {
		return fmt.Errorf("%w: analysis: only implemented for whole modules (no suffix)", derrors.InvalidArgument)
	}
	if req.Binary == "" {
		return fmt.Errorf("%w: analysis: missing binary", derrors.InvalidArgument)
	}
	if req.Binary != path.Base(req.Binary) {
		return fmt.Errorf("%w: analysis: binary name contains slashes (must be a basename)", derrors.InvalidArgument)
	}
	localBinaryPath := path.Join(s.cfg.BinaryDir, req.Binary)
	srcPath := path.Join(analysisBinariesBucketDir, req.Binary)
	const executable = true
	if err := copyToLocalFile(localBinaryPath, executable, srcPath, s.openFile); err != nil {
		return err
	}
	defer derrors.Cleanup(&err, func() error { return os.Remove(localBinaryPath) })

	binaryHash, err := hashFile(localBinaryPath)
	if err != nil {
		return err
	}
	wv := analysis.WorkVersion{
		BinaryArgs:    req.Args,
		WorkerVersion: s.cfg.VersionID,
		SchemaVersion: analysis.SchemaVersion,
		BinaryVersion: hex.EncodeToString(binaryHash),
	}
	key := analysis.WorkVersionKey{Module: req.Module, Version: req.Version, Binary: req.Binary}
	if wv == s.storedWorkVersions[key] {
		log.Infof(ctx, "skipping (work version unchanged): %+v", key)
		updateJob(func(j *jobs.Job) { j.NumSkipped++ })
		return nil
	}
	row := s.scan(ctx, req, localBinaryPath, wv)
	if err := writeResult(ctx, req.Serve, w, s.bqClient, analysis.TableName, row); err != nil {
		return err
	}
	updateJob(func(j *jobs.Job) {
		if row.Error != "" {
			j.NumErrored++
		} else {
			j.NumSucceeded++
		}
	})
	return nil
}

func (s *analysisServer) scan(ctx context.Context, req *analysis.ScanRequest, localBinaryPath string, wv analysis.WorkVersion) *analysis.Result {
	row := &analysis.Result{
		ModulePath:  req.Module,
		Version:     req.Version,
		BinaryName:  req.Binary,
		WorkVersion: wv,
	}
	err := doScan(ctx, req.Module, req.Version, req.Insecure, func() (err error) {
		// Create a module directory. scanInternal will write the module contents there,
		// and both the analysis binary and addSource will read them.
		mdir := moduleDir(req.Module, req.Version)
		defer derrors.Cleanup(&err, func() error { return os.RemoveAll(mdir) })

		jsonTree, err := s.scanInternal(ctx, req, localBinaryPath, mdir)
		if err != nil {
			return err
		}
		info, err := s.proxyClient.Info(ctx, req.Module, req.Version)
		if err != nil {
			return fmt.Errorf("%w: %v", derrors.ProxyError, err)
		}
		row.Version = info.Version
		row.CommitTime = info.Time
		row.Diagnostics = analysis.JSONTreeToDiagnostics(jsonTree)
		return addSource(row.Diagnostics, 1)
	})
	if err != nil {
		switch {
		case isNoModulesSpecified(err):
			// We currently run `go mod download` before running the sandbox
			// and hence implicitly require that the project under analysis
			// is a module. Projects working in GOPATH mode are not supported.
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoModError)
		case isNoRequiredModule(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoRequiredModuleError)
		case isTooManyFiles(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleTooManyOpenFiles)
		case isMissingGoSumEntry(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesMissingGoSumEntryError)
		case isReplacingWithLocalPath(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesImportedLocalError)
		case isModVendor(err):
			err = fmt.Errorf("%v: %w", err, derrors.VendorError)
		default:
		}
		row.AddError(err)
	}
	row.SortVersion = version.ForSorting(row.Version)
	return row
}

func (s *analysisServer) scanInternal(ctx context.Context, req *analysis.ScanRequest, binaryPath, moduleDir string) (jt analysis.JSONTree, err error) {
	const init = true
	if err := prepareModule(ctx, req.Module, req.Version, moduleDir, s.proxyClient, req.Insecure, init); err != nil {
		return nil, err
	}
	var sbox *sandbox.Sandbox
	if !req.Insecure {
		sbox = sandbox.New("/bundle")
		sbox.Runsc = "/usr/local/bin/runsc"
	}
	return runAnalysisBinary(sbox, binaryPath, req.Args, moduleDir)
}

func hashFile(filename string) (_ []byte, err error) {
	defer derrors.Wrap(&err, "hashFile(%q)", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// runAnalysisBinary runs the binary on the module.
func runAnalysisBinary(sbox *sandbox.Sandbox, binaryPath, reqArgs, moduleDir string) (analysis.JSONTree, error) {
	args := []string{"-json"}
	args = append(args, strings.Fields(reqArgs)...)
	args = append(args, "./...")
	out, err := runBinaryInDir(sbox, binaryPath, args, moduleDir)
	if err != nil {
		return nil, fmt.Errorf("running analysis binary %s: %s", binaryPath, derrors.IncludeStderr(err))
	}
	var tree analysis.JSONTree
	if err := json.Unmarshal(out, &tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func runBinaryInDir(sbox *sandbox.Sandbox, path string, args []string, dir string) ([]byte, error) {
	if sbox == nil {
		cmd := exec.Command(path, args...)
		cmd.Dir = dir
		return cmd.Output()
	}
	cmd := sbox.Command(path, args...)
	cmd.Dir = dir
	return cmd.Output()
}

// addSource adds source code lines to the diagnostics.
// Each diagnostic's position includes a full file path and line number.
// addSource reads the file at the line, and includes nContext lines from above
// and below.
func addSource(ds []*analysis.Diagnostic, nContext int) error {
	for _, d := range ds {
		if d.Position == "" {
			// some binaries might collect basic stats, such
			// as number of occurrences of a certain pattern.
			// It might not make sense for them to report a
			// position.
			continue
		}

		file, line, _, err := parsePosition(d.Position)
		if err != nil {
			return err
		}
		source, err := readSource(file, line, nContext)
		if err != nil {
			return fmt.Errorf("reading %s:%d: %w", file, line, err)
		}
		d.Source = bq.NullString{StringVal: source, Valid: true}
	}
	return nil
}

// parsePosition parses a position from a diagnostic.
// Positions are in the format file:line:col.
func parsePosition(pos string) (file string, line, col int, err error) {
	defer derrors.Wrap(&err, "parsePosition(%q)", pos)
	i := strings.LastIndexByte(pos, ':')
	if i < 0 {
		return "", 0, 0, errors.New("missing colon")
	}
	col, err = strconv.Atoi(pos[i+1:])
	if err != nil {
		return "", 0, 0, err
	}
	pos = pos[:i]
	i = strings.LastIndexByte(pos, ':')
	if i < 0 {
		return "", 0, 0, errors.New("missing second colon")
	}
	line, err = strconv.Atoi(pos[i+1:])
	if err != nil {
		return "", 0, 0, err
	}
	return pos[:i], line, col, nil
}

// readSource returns the given line (1-based) from the file, along with
// nContext lines above and below it.
func readSource(file string, line int, nContext int) (_ string, err error) {
	defer derrors.Wrap(&err, "readSource(%q, %d, %d)", file, line, nContext)
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	var lines []string
	n := 0 // 1-based line number
	for scan.Scan() {
		n++
		if n < line-nContext {
			continue
		}
		if n > line+nContext {
			break
		}
		lines = append(lines, scan.Text())
	}
	if scan.Err() != nil {
		return "", scan.Err()
	}
	return strings.Join(lines, "\n"), nil
}

func (s *analysisServer) handleEnqueue(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "analysisServer.handleEnqueue")
	ctx := r.Context()
	params := &analysis.EnqueueParams{Min: defaultMinImportedByCount}
	if err := scan.ParseParams(r, params); err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	mods, err := readModules(ctx, s.cfg, params.File, params.Min)
	if err != nil {
		return err
	}

	var (
		job   *jobs.Job
		jobID string
	)
	// If a user was provided, create a Job.
	if params.User != "" {
		job = jobs.NewJob(params.User, time.Now(), r.URL.String())
		jobID = job.ID()
	}

	tasks := createAnalysisQueueTasks(params, jobID, mods)
	err = enqueueTasks(ctx, tasks, s.queue,
		&queue.Options{Namespace: "analysis", TaskNameSuffix: params.Suffix})
	if err != nil {
		return fmt.Errorf("enequeue failed: %w", err)
	}
	sj := ""
	if job != nil {
		job.NumEnqueued = len(tasks)
		if err := s.jobDB.CreateJob(ctx, job); err != nil {
			sj = fmt.Sprintf(", but could not create job: %v", err)
		} else {
			sj = ", job ID is " + job.ID()
		}
	}
	// Communicate enqueue status for better usability.
	fmt.Fprintf(w, "enqueued %d analysis tasks successfully%s\n", len(tasks), sj)
	return nil
}

func createAnalysisQueueTasks(params *analysis.EnqueueParams, jobID string, mods []scan.ModuleSpec) []queue.Task {
	var tasks []queue.Task
	for _, mod := range mods {
		tasks = append(tasks, &analysis.ScanRequest{
			ModuleURLPath: scan.ModuleURLPath{
				Module:  mod.Path,
				Version: mod.Version,
			},
			ScanParams: analysis.ScanParams{
				Binary:     params.Binary,
				Args:       params.Args,
				ImportedBy: mod.ImportedBy,
				Insecure:   params.Insecure,
				JobID:      jobID,
			},
		})
	}
	return tasks
}
