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
	"sort"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/exp/maps"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
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

type analysisRequest struct {
	scan.ModuleURLPath
	analysisParams
}

// analysisRequest implements queue.Task so it can be put on a TaskQueue.
var _ queue.Task = (*analysisRequest)(nil)

type analysisParams struct {
	Binary     string // name of analysis binary to run
	Args       string // command-line arguments to binary; split on whitespace
	ImportedBy int    // imported-by count of module in path
	Insecure   bool   // if true, run outside sandbox
	Serve      bool   // serve results back to client instead of writing them to BigQuery
}

func (r *analysisRequest) Name() string { return r.Binary + "_" + r.Module + "@" + r.Version }

func (r *analysisRequest) Path() string { return r.ModuleURLPath.Path() }

func (r *analysisRequest) Params() string {
	return scan.FormatParams(r.analysisParams)
}

func parseAnalysisRequest(r *http.Request, prefix string) (*analysisRequest, error) {
	mp, err := scan.ParseModuleURLPath(strings.TrimPrefix(r.URL.Path, prefix))
	if err != nil {
		return nil, err
	}

	ap := analysisParams{}
	if err := scan.ParseParams(r, &ap); err != nil {
		return nil, err
	}
	return &analysisRequest{
		ModuleURLPath:  mp,
		analysisParams: ap,
	}, nil
}

const analysisBinariesBucketDir = "analysis-binaries"

func (s *analysisServer) handleScan(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "analysisServer.handleScan")

	ctx := r.Context()
	req, err := parseAnalysisRequest(r, "/analysis/scan")
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	jsonTree, binaryHash, err := s.scan(ctx, req)
	if err != nil {
		return err
	}

	if req.Serve {
		out, err := json.Marshal(jsonTree)
		if err != nil {
			return err
		}
		_, err = w.Write(out)
		return err
	}
	return s.writeToBigQuery(ctx, req, jsonTree, binaryHash)
}

const sandboxRoot = "/bundle/rootfs"

func (s *analysisServer) scan(ctx context.Context, req *analysisRequest) (_ JSONTree, binaryHash []byte, err error) {
	if req.Binary == "" {
		return nil, nil, fmt.Errorf("%w: analysis: missing binary", derrors.InvalidArgument)
	}
	if req.Suffix != "" {
		return nil, nil, fmt.Errorf("%w: analysis: only implemented for whole modules (no suffix)", derrors.InvalidArgument)
	}

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
func runAnalysisBinary(sbox *sandbox.Sandbox, binaryPath, reqArgs, moduleDir string) (JSONTree, error) {
	args := []string{"-json"}
	args = append(args, strings.Fields(reqArgs)...)
	args = append(args, "./...")
	out, err := runBinaryInDir(sbox, binaryPath, args, moduleDir)
	if err != nil {
		return nil, fmt.Errorf("running analysis binary %s: %s", binaryPath, derrors.IncludeStderr(err))
	}
	var tree JSONTree
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

type diagnosticsOrError struct {
	Diagnostics []JSONDiagnostic
	Error       *jsonError
}

func (de *diagnosticsOrError) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &de.Diagnostics); err == nil {
		return nil
	}
	return json.Unmarshal(data, &de.Error)
}

////////////////////////////////////////////////////////////////

// These structs were copied, with minor changes, from
// golang.org/x/tools/go/analysis/internal/analysisflags.

// A JSONTree is a mapping from package ID to analysis name to result.
// Each result is either a jsonError or a list of JSONDiagnostic.
type JSONTree map[string]map[string]diagnosticsOrError

// A JSONDiagnostic can be used to encode and decode analysis.Diagnostics to and
// from JSON.
type JSONDiagnostic struct {
	Category       string             `json:"category,omitempty"`
	Posn           string             `json:"posn"`
	Message        string             `json:"message"`
	SuggestedFixes []JSONSuggestedFix `json:"suggested_fixes,omitempty"`
}

// A JSONSuggestedFix describes an edit that should be applied as a whole or not
// at all. It might contain multiple TextEdits/text_edits if the SuggestedFix
// consists of multiple non-contiguous edits.
type JSONSuggestedFix struct {
	Message string         `json:"message"`
	Edits   []JSONTextEdit `json:"edits"`
}

// A TextEdit describes the replacement of a portion of a file.
// Start and End are zero-based half-open indices into the original byte
// sequence of the file, and New is the new text.
type JSONTextEdit struct {
	Filename string `json:"filename"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	New      string `json:"new"`
}

type jsonError struct {
	Err string `json:"error"`
}

func (s *analysisServer) writeToBigQuery(ctx context.Context, req *analysisRequest, jsonTree JSONTree, binaryHash []byte) (err error) {
	defer derrors.Wrap(&err, "analysisServer.writeToBigQuery(%q, %q)", req.Module, req.Version)
	row := &bigquery.AnalysisResult{
		ModulePath: req.Module,
		BinaryName: req.Binary,
		AnalysisWorkVersion: bigquery.AnalysisWorkVersion{
			BinaryVersion: hex.EncodeToString(binaryHash),
			BinaryArgs:    req.Args,
			WorkerVersion: s.cfg.VersionID,
			SchemaVersion: bigquery.AnalysisSchemaVersion,
		},
	}
	info, err := s.proxyClient.Info(ctx, req.Module, req.Version)
	if err != nil {
		log.Errorf(ctx, err, "proxy error")
		row.AddError(fmt.Errorf("%v: %w", err, derrors.ProxyError))
		return nil
	}
	row.Version = info.Version
	row.SortVersion = version.ForSorting(row.Version)
	row.CommitTime = info.Time

	row.Diagnostics = jsonTreeToDiagnostics(jsonTree)
	if s.bqClient == nil {
		log.Infof(ctx, "bigquery disabled, not uploading")
	} else {
		log.Infof(ctx, "uploading to bigquery: %s", req.Path())
		if err := s.bqClient.Upload(ctx, bigquery.AnalysisTableName, row); err != nil {
			// This is often caused by:
			// "Upload: googleapi: got HTTP response code 413 with body"
			// which happens for some modules.
			row.AddError(fmt.Errorf("%v: %w", err, derrors.BigQueryError))
			log.Errorf(ctx, err, "bq.Upload for %s", req.Path())
		}
	}
	return nil
}

// jsonTreeToDiagnostics converts a jsonTree to a list of diagnostics for BigQuery.
// It ignores the suggested fixes of the diagnostics.
func jsonTreeToDiagnostics(jsonTree JSONTree) []*bigquery.Diagnostic {
	var diags []*bigquery.Diagnostic
	// Sort for determinism.
	pkgIDs := maps.Keys(jsonTree)
	sort.Strings(pkgIDs)
	for _, pkgID := range pkgIDs {
		amap := jsonTree[pkgID]
		aNames := maps.Keys(amap)
		sort.Strings(aNames)
		for _, aName := range aNames {
			diagsOrErr := amap[aName]
			if diagsOrErr.Error != nil {
				diags = append(diags, &bigquery.Diagnostic{
					PackageID:    pkgID,
					AnalyzerName: aName,
					Error:        diagsOrErr.Error.Err,
				})
			} else {
				for _, jd := range diagsOrErr.Diagnostics {
					diags = append(diags, &bigquery.Diagnostic{
						PackageID:    pkgID,
						AnalyzerName: aName,
						Category:     jd.Category,
						Position:     jd.Posn,
						Message:      jd.Message,
					})
				}
			}
		}
	}
	return diags
}
