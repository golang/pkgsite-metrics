// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package govulncheck provides functionality for manipulating
// inputs and outputs of govulncheck endpoints.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	bq "cloud.google.com/go/bigquery"

	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/fstore"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/osv"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

const (
	// ModeBinary runs the govulncheck binary in binary mode.
	ModeBinary string = "BINARY"

	// ModeGovulncheck runs the govulncheck binary in default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"

	// FlagBinary is the flag passed to govulncheck to run in binary mode.
	FlagBinary = "binary"

	// FlagSource is the flag passed to govulncheck to run in source mode.
	FlagSource = "source"
)

// EnqueueQueryParams for govulncheck/enqueue.
type EnqueueQueryParams struct {
	Suffix string // appended to task queue IDs to generate unique tasks
	Mode   string // type of analysis to run
	Min    int    // minimum import-by count for a module to be included
	File   string // path to file containing modules; if missing, use DB
}

// Request contains information passed to a scan endpoint.
type Request struct {
	scan.ModuleURLPath
	QueryParams
}

// QueryParams has query parameters for a govulncheck scan request.
type QueryParams struct {
	ImportedBy int    // imported-by count
	Mode       string // govulncheck mode
	Insecure   bool   // if true, run outside sandbox
	Serve      bool   // serve results back to client instead of writing them to BigQuery
}

// The below methods implement queue.Task.

func (r *Request) Name() string { return r.Module + "@" + r.Version }

func (r *Request) Path() string { return r.ModuleURLPath.Path() }

func (r *Request) Params() string {
	return scan.FormatParams(r.QueryParams)
}

// ParseRequest parses an http request r for an endpoint
// prefix and produces a corresponding ScanRequest.
//
// The module and version should have one of the following three forms:
//   - <module>/@v/<version>
//   - <module>@<version>
//   - <module>/@latest
//
// (These are the same forms that the module proxy accepts.)
func ParseRequest(r *http.Request, prefix string) (*Request, error) {
	mp, err := scan.ParseModuleURLPath(strings.TrimPrefix(r.URL.Path, prefix))
	if err != nil {
		return nil, err
	}

	rp := QueryParams{ImportedBy: -1}
	if err := scan.ParseParams(r, &rp); err != nil {
		return nil, err
	}
	if rp.ImportedBy < 0 {
		return nil, errors.New(`missing or negative "importedby" query param`)
	}
	return &Request{
		ModuleURLPath: mp,
		QueryParams:   rp,
	}, nil
}

// ConvertGovulncheckFinding takes a finding from govulncheck and converts it to
// a bigquery vuln.
func ConvertGovulncheckFinding(f *govulncheckapi.Finding, o *osv.Entry) *Vuln {
	vulnerableFrame := f.Trace[0]
	reviewed := ""
	if o != nil && o.DatabaseSpecific != nil { // sanity
		reviewed = o.DatabaseSpecific.ReviewStatus.String()
	}
	return &Vuln{
		ID:          f.OSV,
		PackagePath: vulnerableFrame.Package,
		ModulePath:  vulnerableFrame.Module,
		Version:     vulnerableFrame.Version,
		ReviewStatus: bq.NullString{
			StringVal: reviewed,
			Valid:     reviewed != "",
		},
	}
}

const TableName = "govulncheck"

// Note: before modifying Result or Vuln, make sure the change
// is a valid schema modification.
// The only supported changes are:
//   - adding a nullable or repeated column
//   - dropping a column
//   - changing a column from required to nullable.
// See https://cloud.google.com/bigquery/docs/managing-table-schemas for details.

// Result is a row in the BigQuery govulncheck table.
type Result struct {
	CreatedAt     time.Time `bigquery:"created_at"`
	ModulePath    string    `bigquery:"module_path"`
	Version       string    `bigquery:"version"`
	Suffix        string    `bigquery:"suffix"`
	SortVersion   string    `bigquery:"sort_version"`
	ImportedBy    int       `bigquery:"imported_by"`
	Error         string    `bigquery:"error"`
	ErrorCategory string    `bigquery:"error_category"`
	CommitTime    time.Time `bigquery:"commit_time"`
	ScanSeconds   float64   `bigquery:"scan_seconds"`
	// BinaryBuildSeconds is populated only in COMPARE - BINARY mode
	BinaryBuildSeconds bq.NullFloat64 `bigquery:"build_seconds"`
	ScanMemory         int64          `bigquery:"scan_memory"`
	ScanMode           string         `bigquery:"scan_mode"`
	WorkVersion                       // InferSchema flattens embedded fields
	Vulns              []*Vuln        `bigquery:"vulns"`
}

// WorkState returns a WorkState for the Result.
func (r *Result) WorkState() *WorkState {
	return &WorkState{
		WorkVersion:   &r.WorkVersion,
		ErrorCategory: r.ErrorCategory,
	}
}

// WorkVersion contains information that can be used to avoid duplicate work.
// Given two WorkVersion values v1 and v2 for the same module path and version,
// if v1.Equal(v2) then it is not necessary to scan the module.
type WorkVersion struct {
	// GoVersion used at path. Allows precise interpretation
	// of detected stdlib vulnerabilities.
	GoVersion string `bigquery:"go_version"`
	// The version of the currently running code. This tracks changes in the
	// logic of module scanning and processing.
	WorkerVersion string `bigquery:"worker_version"`
	// The version of the bigquery schema.
	SchemaVersion string ` bigquery:"schema_version"`
	// When the vuln DB was last modified.
	VulnDBLastModified time.Time `bigquery:"vulndb_last_modified"`
}

func (v1 *WorkVersion) Equal(v2 *WorkVersion) bool {
	if v1 == nil || v2 == nil {
		return false
	}
	return v1.GoVersion == v2.GoVersion &&
		v1.WorkerVersion == v2.WorkerVersion &&
		v1.SchemaVersion == v2.SchemaVersion &&
		v1.VulnDBLastModified.Equal(v2.VulnDBLastModified)
}

func (vr *Result) SetUploadTime(t time.Time) { vr.CreatedAt = t }

func (vr *Result) AddError(err error) {
	if err == nil {
		return
	}
	vr.Error = err.Error()
	vr.ErrorCategory = derrors.CategorizeError(err)
}

// Vuln is a record in Result.
type Vuln struct {
	ID          string `bigquery:"id"`
	PackagePath string `bigquery:"package_path"`
	ModulePath  string `bigquery:"module_path"`
	Version     string `bigquery:"version"`
	// ReviewStatus is a field of osv. However,
	// we don't have the osv field, yet only its
	// ID. To avoid joining tables with osv tables
	// that do not exist in ecosystem metrics, we
	// just put the review status here instead.
	ReviewStatus bq.NullString `bigquery:"review_status"`
}

// SchemaVersion changes whenever the govulncheck schema changes.
var SchemaVersion string

func init() {
	s, err := bigquery.InferSchema(Result{})
	if err != nil {
		panic(err)
	}
	SchemaVersion = bigquery.SchemaVersion(s)
	bigquery.AddTable(TableName, s)
}

type WorkState struct {
	WorkVersion   *WorkVersion
	ErrorCategory string
}

// ScanStats contains monitoring information for a govulncheck run.
type ScanStats struct {
	// ScanSeconds is the amount of time a scan took to run, in seconds.
	ScanSeconds float64
	// ScanMemory is the peak (heap) memory used by govulncheck, in kb.
	ScanMemory uint64
	// BuildTime is the amount of time it takes to build a given binary
	// *BEFORE* scanning it with govulncheck.
	// This is only used in COMPARE - BINARY mode
	BuildTime time.Duration
}

// AnalysisResponse contains the raw govulncheck result
// and statistics about memory usage and run time of invoking
// govulncheck on source code or a binary. Used when
// running govulncheck inside and outside of a sandbox.
type AnalysisResponse struct {
	Findings []*govulncheckapi.Finding
	OSVs     map[string]*osv.Entry
	Stats    ScanStats
}

func UnmarshalAnalysisResponse(output []byte) (*AnalysisResponse, error) {
	var e struct{ Error string }
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res AnalysisResponse
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// CompareResponse contains results running govulncheck on a binary
// and corresponding source code.
type CompareResponse struct {
	// Map from package import path to pair of binary & source mode findings
	FindingsForMod map[string]*ComparePair
}

type ComparePair struct {
	BinaryResults AnalysisResponse
	SourceResults AnalysisResponse
	Error         string
}

func UnmarshalCompareResponse(output []byte) (*CompareResponse, error) {
	var e struct{ Error string }
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res CompareResponse
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func RunGovulncheckCmd(govulncheckPath, modeFlag, pattern, moduleDir, vulndbDir string) (*AnalysisResponse, error) {
	stdOut := bytes.Buffer{}
	stdErr := bytes.Buffer{}
	uri := "file://" + vulndbDir
	if runtime.GOOS == "windows" {
		uri = "file:///" + filepath.ToSlash(vulndbDir)
	}
	args := []string{"-mode", modeFlag, "-json", "-db", uri}
	if moduleDir != "" {
		args = append(args, "-C", moduleDir)
	}
	args = append(args, pattern)
	govulncheckCmd := exec.Command(govulncheckPath, args...)

	govulncheckCmd.Stdout = &stdOut
	govulncheckCmd.Stderr = &stdErr

	start := time.Now()
	if err := govulncheckCmd.Run(); err != nil {
		return nil, errors.New(stdErr.String())
	}
	end := time.Now()

	handler := NewMetricsHandler()
	err := govulncheckapi.HandleJSON(&stdOut, handler)
	if err != nil {
		return nil, err
	}
	return &AnalysisResponse{
		Findings: handler.Findings(),
		OSVs:     handler.OSVs(),
		Stats: ScanStats{
			ScanSeconds: end.Sub(start).Seconds(),
			ScanMemory:  getMemoryUsage(govulncheckCmd),
		},
	}, nil
}

// getMemoryUsage is overridden with a Unix-specific function on Linux.
var getMemoryUsage = func(c *exec.Cmd) uint64 {
	return 0
}

const collName = "GovulncheckWorkStates"

// SetWorkState writes the work state for modulePath@version.
func SetWorkState(ctx context.Context, ns *fstore.Namespace, modulePath, version string, ws *WorkState) (err error) {
	defer func() {
		log.Debugf(ctx, "SetWorkState(%s@%s, %+v) => %v", modulePath, version, ws, err)
	}()
	dr := ns.Collection(collName).Doc(docName(modulePath, version))
	return fstore.Set[WorkState](ctx, dr, ws)
}

// GetWorkState reads the work state for modulePath@version.
// If there is none, it returns (nil, nil).
func GetWorkState(ctx context.Context, ns *fstore.Namespace, modulePath, version string) (ws *WorkState, err error) {
	defer func() {
		log.Debugf(ctx, "GetWorkState(%s@%s) => (%+v, %v)", modulePath, version, ws, err)
	}()

	defer derrors.Wrap(&err, "ReadWorkState(%q, %q)", modulePath, version)
	dr := ns.Collection(collName).Doc(docName(modulePath, version))
	ws, err = fstore.Get[WorkState](ctx, dr)
	if errors.Is(err, derrors.NotFound) {
		return nil, nil
	}
	return ws, err
}

// docName returns a valid Firestore document name for the given module path and version.
// It escapes slashes, since Firestore treats them specially.
func docName(modulePath, version string) string {
	return url.PathEscape(modulePath + "@" + version)
}
