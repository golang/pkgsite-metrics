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
	"path/filepath"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	return &analysisServer{
		Server:             s,
		openFile:           gcsOpenFileFunc(ctx, bucket),
		storedWorkVersions: make(map[analysis.WorkVersionKey]analysis.WorkVersion),
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

	// incrementJob increments name value by 1 for the current job.
	// If there is an error, it logs it instead of failing.
	incrementJob := func(name string) {
		if req.JobID != "" && s.jobDB != nil {
			// There can be contention on updating job stats,
			// in which case we retry it a few times.
			retries := 0
			for {
				if err := s.jobDB.Increment(ctx, req.JobID, name, 1); err != nil {
					if e := status.Code(err); e == codes.Aborted && retries < 5 {
						time.Sleep(50 * time.Millisecond * (1 << retries))
						retries++
						continue
					}
					log.Errorf(ctx, err, "failed to update job for id %q", req.JobID)
				}
				return
			}
		}
	}

	incrementJob("NumStarted")

	// Handle errors here.
	defer func() {
		if err != nil {
			incrementJob("NumFailed")
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
	if binaryHash != req.BinaryVersion {
		return fmt.Errorf("%w: analysis: for binary %s, hash of download file %s does not match hash in request %s",
			derrors.InvalidArgument, req.Binary, binaryHash, req.BinaryVersion)
	}
	wv := analysis.WorkVersion{
		BinaryArgs:    req.Args,
		WorkerVersion: s.cfg.VersionID,
		SchemaVersion: analysis.SchemaVersion,
		BinaryVersion: binaryHash,
	}

	if err := s.readWorkVersion(ctx, req.Module, req.Version, req.Binary); err != nil {
		return err
	}
	key := analysis.WorkVersionKey{Module: req.Module, Version: req.Version, Binary: req.Binary}
	if wv == s.storedWorkVersions[key] {
		log.Infof(ctx, "skipping (work version unchanged): %+v", key)
		incrementJob("NumSkipped")
		return nil
	}

	row := s.scan(ctx, req, localBinaryPath, wv)
	if err := writeResult(ctx, req.Serve, w, s.bqClient, analysis.TableName, row); err != nil {
		return err
	}
	if row.Error != "" {
		incrementJob("NumErrored")
	} else {
		incrementJob("NumSucceeded")
	}
	return nil
}

func (s *analysisServer) readWorkVersion(ctx context.Context, module_path, version, binary string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := analysis.WorkVersionKey{Module: module_path, Version: version, Binary: binary}
	if _, ok := s.storedWorkVersions[key]; ok {
		return nil
	}
	if s.bqClient == nil {
		return nil
	}
	wv, err := analysis.ReadWorkVersion(ctx, s.bqClient, module_path, version, binary)
	if err != nil {
		return err
	}
	if wv != nil {
		s.storedWorkVersions[key] = *wv
	}
	return nil
}

func (s *analysisServer) scan(ctx context.Context, req *analysis.ScanRequest, localBinaryPath string, wv analysis.WorkVersion) *analysis.Result {
	row := &analysis.Result{
		ModulePath:  req.Module,
		JobID:       req.JobID,
		Version:     req.Version,
		BinaryName:  req.Binary,
		WorkVersion: wv,
	}
	hasGoMod := true
	err := doScan(ctx, req.Module, req.Version, req.Insecure, func() (err error) {
		// Create a module directory. scanInternal will write the module contents there,
		// and both the analysis binary and addSource will read them.
		modDir := moduleDir(req.Module, req.Version)
		if err := os.MkdirAll(modDir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to mkdir %s: %w", modDir, err)
		}
		defer derrors.Cleanup(&err, func() error { return os.RemoveAll(modDir) })

		jsonTree, err := s.scanInternal(ctx, req, localBinaryPath, modDir)
		if err != nil {
			return err
		}
		hasGoMod = fileExists(filepath.Join(modDir, "go.mod")) // for precise error breakdown
		info, err := s.proxyClient.Info(ctx, req.Module, req.Version)
		if err != nil {
			return fmt.Errorf("%w: %v", derrors.ProxyError, err)
		}
		row.Version = info.Version
		row.CommitTime = info.Time
		row.Diagnostics = analysis.JSONTreeToDiagnostics(jsonTree)
		return addSource(ctx, row.Diagnostics, 1)
	})
	if err != nil {
		// The errors are classified as to explicitly make a distinction
		// between misc errors for modules and non-modules. The intended
		// audience for analysis pipeline will directly look at errors.
		// Without this distinction, experiments where there are a lot of
		// misc errors might sway users into thinking that something is
		// wrong with their analysis, while in fact it can be the case
		// that synthetic (non-modules) are just outdated.
		switch {
		case isNoModulesSpecified(err):
			// We try to turn every non-module project into a module, so this
			// branch should never be reached. We keep this for sanity and to
			// catch any regressions.
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoModError)
		case isModVendor(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadVendorError)
		case isNoRequiredModule(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoRequiredModuleError)
		case isTooManyFiles(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleTooManyOpenFiles)
		case isMissingGoSumEntry(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesMissingGoSumEntryError)
		case isReplacingWithLocalPath(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesImportedLocalError)
		case isProxyCacheMiss(err):
			err = fmt.Errorf("%v: %w", err, derrors.ProxyError)
		case isSandboxRelatedIssue(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleSandboxError)
		case isBuildIssue(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesError)
		case !hasGoMod:
			// Classify misc errors on synthetic modules separately.
			err = fmt.Errorf("%v: %w", err, derrors.ScanSyntheticModuleError)
		default:
		}
		row.AddError(err)
	}
	row.SortVersion = version.ForSorting(row.Version)
	return row
}

func (s *analysisServer) scanInternal(ctx context.Context, req *analysis.ScanRequest, binaryPath, moduleDir string) (jt analysis.JSONTree, err error) {
	prepareArgs := prepareModuleArgs{
		modulePath:  req.Module,
		version:     req.Version,
		dir:         moduleDir,
		proxyClient: s.proxyClient,
		insecure:    req.Insecure,
		init:        !req.SkipInit,
		noDeps:      req.NoDeps,
	}
	if err := prepareModule(ctx, prepareArgs); err != nil {
		return nil, err
	}
	var sbox *sandbox.Sandbox
	if !req.Insecure {
		sbox = sandbox.New("/bundle")
		sbox.Runsc = "/usr/local/bin/runsc"
	}

	analysisArgs := req.Args + " " + filepath.Join(req.Module, "...")
	return runAnalysisBinary(sbox, binaryPath, analysisArgs, moduleDir)
}

func hashFile(filename string) (_ string, err error) {
	defer derrors.Wrap(&err, "hashFile(%q)", filename)
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runAnalysisBinary runs the binary on the module.
func runAnalysisBinary(sbox *sandbox.Sandbox, binaryPath, reqArgs, moduleDir string) (analysis.JSONTree, error) {
	args := []string{"-json"}
	args = append(args, strings.Fields(reqArgs)...)
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
func addSource(ctx context.Context, ds []*analysis.Diagnostic, nContext int) error {
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

		if url, err := sourceURL(d.Position, line); err == nil {
			d.Position = url
		} else {
			// URL creation failure should not result in an error of the analysis run.
			log.Errorf(ctx, err, "url creation failed for position %s", d.Position)
		}
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

// sourceURL creates a URL showing the code corresponding to
// position pos and highlighting line.
func sourceURL(pos string, line int) (string, error) {
	// Trim /tmp/modules/ from the position string.
	relPos := strings.TrimPrefix(pos, modulesDir+"/")
	if relPos == pos {
		return "", errors.New("unexpected prefix")
	}
	i := strings.IndexByte(relPos, ':')
	if i < 0 {
		return "", errors.New("missing colon in position")
	}
	path := relPos[:i]
	return fmt.Sprintf("https://go-mod-viewer.appspot.com/%s#L%d", path, line), nil

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
	params := &analysis.EnqueueParams{Min: defaultMinImportedByCount, Max: defaultMaxImportedByCount, SkipInit: true}
	if err := scan.ParseParams(r, params); err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	if params.Min > params.Max {
		return fmt.Errorf("%w: analysis: bad min/max range", derrors.InvalidArgument)
	}
	if params.Binary == "" {
		return fmt.Errorf("%w: analysis: missing binary", derrors.InvalidArgument)
	}
	if params.Binary != path.Base(params.Binary) {
		return fmt.Errorf("%w: analysis: binary name contains slashes (must be a basename)", derrors.InvalidArgument)
	}
	srcPath := path.Join(analysisBinariesBucketDir, params.Binary)
	rc, err := s.openFile(srcPath)
	if err != nil {
		return err
	}
	defer rc.Close()
	binaryHash, err := hashReader(rc)
	if err != nil {
		return err
	}
	mods, err := readModules(ctx, s.cfg, params.File, params.Min, params.Max)
	if err != nil {
		return err
	}

	// If a user was provided, create a Job.
	var jobID string
	sj := ""
	if params.User != "" {
		job := jobs.NewJob(params.User, time.Now(), r.URL.String(), params.Binary, binaryHash, params.Args)
		jobID = job.ID()
		if err := s.jobDB.CreateJob(ctx, job); err != nil {
			sj = fmt.Sprintf(", but could not create job: %v", err)
		} else {
			sj = ", job ID is " + jobID
		}
	}

	tasks := createAnalysisQueueTasks(params, jobID, binaryHash, mods)
	err = enqueueTasks(ctx, tasks, s.queue,
		&queue.Options{Namespace: "analysis", TaskNameSuffix: params.Suffix})
	if err != nil {
		if err := s.jobDB.DeleteJob(ctx, jobID); err != nil {
			log.Errorf(ctx, err, "failed to delete job upon unsuccessful enqueuing")
		}
		return fmt.Errorf("enequeue failed: %w", err)
	}
	if jobID != "" {
		s.jobDB.Increment(ctx, jobID, "NumEnqueued", len(tasks))
	}
	// Communicate enqueue status for better usability.
	fmt.Fprintf(w, "enqueued %d analysis tasks successfully%s\n", len(tasks), sj)
	return nil
}

func createAnalysisQueueTasks(params *analysis.EnqueueParams, jobID string, binaryVersion string, mods []scan.ModuleSpec) []queue.Task {
	var tasks []queue.Task
	for _, mod := range mods {
		tasks = append(tasks, &analysis.ScanRequest{
			ModuleURLPath: scan.ModuleURLPath{
				Module:  mod.Path,
				Version: mod.Version,
			},
			ScanParams: analysis.ScanParams{
				Binary:        params.Binary,
				BinaryVersion: binaryVersion,
				Args:          params.Args,
				ImportedBy:    mod.ImportedBy,
				Insecure:      params.Insecure,
				JobID:         jobID,
				SkipInit:      params.SkipInit,
				NoDeps:        params.NoDeps,
			},
		})
	}
	return tasks
}
