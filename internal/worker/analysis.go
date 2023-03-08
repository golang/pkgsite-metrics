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
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/modules"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/scan"
	"golang.org/x/pkgsite-metrics/internal/version"
)

type analysisServer struct {
	*Server
}

const analysisBinariesBucketDir = "analysis-binaries"

func (s *analysisServer) handleScan(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "analysisServer.handleScan")

	ctx := r.Context()
	req, err := analysis.ParseScanRequest(r, "/analysis/scan")
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	if req.Binary == "" {
		return fmt.Errorf("%w: analysis: missing binary", derrors.InvalidArgument)
	}
	if req.Suffix != "" {
		return fmt.Errorf("%w: analysis: only implemented for whole modules (no suffix)", derrors.InvalidArgument)
	}

	row := s.scan(ctx, req)
	return writeResult(ctx, req.Serve, w, s.bqClient, analysis.TableName, row)
}

const sandboxRoot = "/bundle/rootfs"

func (s *analysisServer) scan(ctx context.Context, req *analysis.ScanRequest) *analysis.Result {
	row := &analysis.Result{
		ModulePath: req.Module,
		Version:    req.Version,
		BinaryName: req.Binary,
		WorkVersion: analysis.WorkVersion{
			BinaryArgs:    req.Args,
			WorkerVersion: s.cfg.VersionID,
			SchemaVersion: analysis.SchemaVersion,
		},
	}

	err := doScan(ctx, req.Module, req.Version, req.Insecure, func() error {
		jsonTree, binaryHash, err := s.scanInternal(ctx, req)
		if err != nil {
			return err
		}
		row.WorkVersion.BinaryVersion = hex.EncodeToString(binaryHash)
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

func (s *analysisServer) scanInternal(ctx context.Context, req *analysis.ScanRequest) (jt analysis.JSONTree, binaryHash []byte, err error) {
	var tempDir string
	if req.Insecure {
		tempDir, err = os.MkdirTemp("", "analysis")
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			err1 := os.RemoveAll(tempDir)
			if err == nil {
				err = err1
			}
		}()
	}

	var destPath string
	if req.Insecure {
		destPath = filepath.Join(tempDir, "binary")
	} else {
		destPath = path.Join(sandboxRoot, "binaries", path.Base(req.Binary))
	}
	if err := copyBinary(ctx, destPath, req.Binary, s.cfg.BinaryBucket); err != nil {
		return nil, nil, err
	}
	binaryHash, err = hashFile(destPath)
	if err != nil {
		return nil, nil, err
	}

	if !req.Insecure {
		sandboxDir, cleanup, err := downloadModuleSandbox(ctx, req.Module, req.Version, s.proxyClient)
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()
		log.Infof(ctx, "running %s on %s@%s in sandbox", req.Binary, req.Module, req.Version)
		sbox := sandbox.New("/bundle")
		sbox.Runsc = "/usr/local/bin/runsc"
		tree, err := runAnalysisBinary(sbox, strings.TrimPrefix(destPath, sandboxRoot), req.Args, sandboxDir)
		if err != nil {
			return nil, nil, err
		}
		return tree, binaryHash, nil
	}
	// Insecure mode.
	// Download the module.
	log.Debugf(ctx, "fetching module zip: %s@%s", req.Module, req.Version)
	const stripModulePrefix = true
	if err := modules.Download(ctx, req.Module, req.Version, tempDir, s.proxyClient, stripModulePrefix); err != nil {
		return nil, nil, err
	}
	tree, err := runAnalysisBinary(nil, destPath, req.Args, tempDir)
	if err != nil {
		return nil, nil, err
	}
	return tree, binaryHash, nil
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

// copyBinary copies a binary from srcPath to destPath.
// If binaryBucket is non-empty, it reads srcPath from that GCS bucket.
// If binaryBucket is empty, return an error.
func copyBinary(ctx context.Context, destPath, srcPath, binaryBucket string) error {
	if binaryBucket == "" {
		return errors.New("missing binary bucket (define GO_ECOSYSTEM_BINARY_BUCKET)")
	}
	c, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	bucket := c.Bucket(binaryBucket)
	bucketPath := path.Join(analysisBinariesBucketDir, srcPath)
	return copyFromGCS(ctx, bucket, bucketPath, destPath, true)
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
