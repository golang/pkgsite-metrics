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
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

const (
	// ModeBinary runs the govulncheck binary in binary mode.
	ModeBinary string = "BINARY"

	// ModeGovulncheck runs the govulncheck binary in default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"
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
func ConvertGovulncheckFinding(f *govulncheckapi.Finding) *Vuln {
	vulnerableFrame := f.Trace[0]
	vuln := &Vuln{
		ID:          f.OSV,
		PackagePath: vulnerableFrame.Package,
		ModulePath:  vulnerableFrame.Module,
		Version:     vulnerableFrame.Version,
		Called:      false,
	}
	if vulnerableFrame.Function != "" {
		vuln.Called = true
	}

	return vuln
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
	ScanMemory    int64     `bigquery:"scan_memory"`
	ScanMode      string    `bigquery:"scan_mode"`
	WorkVersion             // InferSchema flattens embedded fields
	Vulns         []*Vuln   `bigquery:"vulns"`
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
		return v1 == v2
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
	// Called is currently used to differentiate between
	// called and imported vulnerabilities. We need it
	// because we don't conduct an imports analysis yet
	// use the full results of govulncheck source analysis.
	// It is not part of the bigquery schema.
	Called bool `bigquery:"-"`
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

// ReadWorkStates reads the most recent work versions in the govulncheck table
// together with their accompanying error categories.
func ReadWorkStates(ctx context.Context, c *bigquery.Client) (_ map[[2]string]*WorkState, err error) {
	defer derrors.Wrap(&err, "ReadWorkStates")
	m := map[[2]string]*WorkState{}
	query := bigquery.PartitionQuery{
		Table:       c.FullTableName(TableName),
		Columns:     "module_path, version, go_version, worker_version, schema_version, vulndb_last_modified, error_category",
		PartitionOn: "module_path, sort_version",
		OrderBy:     "created_at DESC",
	}.String()
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	err = bigquery.ForEachRow(iter, func(r *Result) bool {
		m[[2]string{r.ModulePath, r.Version}] = &WorkState{
			WorkVersion:   &r.WorkVersion,
			ErrorCategory: r.ErrorCategory,
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ScanStats contains monitoring information for a govulncheck run.
type ScanStats struct {
	// ScanSeconds is the amount of time a scan took to run, in seconds.
	ScanSeconds float64
	// ScanMemory is the peak (heap) memory used by govulncheck, in kb.
	ScanMemory uint64
}

// SandboxResponse contains the raw govulncheck result
// and statistics about memory usage and run time. Used
// for capturing result of govulncheck run in a sandbox.
type SandboxResponse struct {
	Findings []*govulncheckapi.Finding
	Stats    ScanStats
}

func UnmarshalSandboxResponse(output []byte) (*SandboxResponse, error) {
	var e struct{ Error string }
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res SandboxResponse
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func RunGovulncheckCmd(govulncheckPath, mode, modulePath, vulndbDir string, stats *ScanStats) ([]*govulncheckapi.Finding, error) {
	pattern := "./..."
	dir := ""

	var modeFlag string
	if mode == ModeBinary {
		pattern = modulePath
		modeFlag = "binary"
	} else {
		dir = modulePath
		modeFlag = "source"
	}

	stdOut := bytes.Buffer{}
	stdErr := bytes.Buffer{}
	govulncheckCmd := exec.Command(govulncheckPath, "-mode", modeFlag,
		"-json", "-db=file://"+vulndbDir, "-C="+dir, pattern)

	govulncheckCmd.Stdout = &stdOut
	govulncheckCmd.Stderr = &stdErr

	start := time.Now()
	if err := govulncheckCmd.Run(); err != nil {
		return nil, errors.New(stdErr.String())
	}
	stats.ScanSeconds = time.Since(start).Seconds()
	stats.ScanMemory = uint64(govulncheckCmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss)

	handler := NewMetricsHandler()
	err := govulncheckapi.HandleJSON(&stdOut, handler)
	if err != nil {
		return nil, err
	}
	return handler.Findings(), nil
}
