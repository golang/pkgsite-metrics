// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
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
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/derrors"
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
		return nil
	}
	row := s.scan(ctx, req, localBinaryPath, wv)
	return writeResult(ctx, req.Serve, w, s.bqClient, analysis.TableName, row)
}

func (s *analysisServer) scan(ctx context.Context, req *analysis.ScanRequest, localBinaryPath string, wv analysis.WorkVersion) *analysis.Result {
	row := &analysis.Result{
		ModulePath:  req.Module,
		Version:     req.Version,
		BinaryName:  req.Binary,
		WorkVersion: wv,
	}
	err := doScan(ctx, req.Module, req.Version, req.Insecure, func() error {
		jsonTree, err := s.scanInternal(ctx, req, localBinaryPath)
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
		return nil
	})
	if err != nil {
		row.AddError(err)
	}
	row.SortVersion = version.ForSorting(row.Version)
	return row
}

func (s *analysisServer) scanInternal(ctx context.Context, req *analysis.ScanRequest, binaryPath string) (jt analysis.JSONTree, err error) {
	mdir := moduleDir(req.Module, req.Version)
	defer derrors.Cleanup(&err, func() error { return os.RemoveAll(mdir) })
	if err := prepareModule(ctx, req.Module, req.Version, mdir, s.proxyClient, req.Insecure); err != nil {
		return nil, err
	}
	var sbox *sandbox.Sandbox
	if !req.Insecure {
		sbox = sandbox.New("/bundle")
		sbox.Runsc = "/usr/local/bin/runsc"
	}
	tree, err := runAnalysisBinary(sbox, binaryPath, req.Args, mdir)
	if err != nil {
		return nil, err
	}
	return tree, nil
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

// Run the binary on the module.
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
	tasks := createAnalysisQueueTasks(params, mods)
	return enqueueTasks(ctx, tasks, s.queue,
		&queue.Options{Namespace: "analysis", TaskNameSuffix: params.Suffix})
}

func createAnalysisQueueTasks(params *analysis.EnqueueParams, mods []scan.ModuleSpec) []queue.Task {
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
			},
		})
	}
	return tasks
}
