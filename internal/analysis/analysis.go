// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package analysis provides functionality for manipulating
// inputs and outputs of analysis endpoints.
package analysis

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	bq "cloud.google.com/go/bigquery"
	"golang.org/x/exp/maps"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

type ScanRequest struct {
	scan.ModuleURLPath
	ScanParams
}

type ScanParams struct {
	Binary     string // name of analysis binary to run
	Args       string // command-line arguments to binary; split on whitespace
	ImportedBy int    // imported-by count of module in path
	Insecure   bool   // if true, run outside sandbox
	Serve      bool   // serve results back to client instead of writing them to BigQuery
}

type EnqueueParams struct {
	Binary   string // name of analysis binary to run
	Args     string // command-line arguments to binary; split on whitespace
	Insecure bool   // if true, run outside sandbox
	Min      int    // minimum import-by count for a module to be included
	File     string // path to file containing modules; if missing, use DB
	Suffix   string // appended to task queue IDs to generate unique tasks
}

// Request implements queue.Task so it can be put on a TaskQueue.
var _ queue.Task = (*ScanRequest)(nil)

func (r *ScanRequest) Name() string { return r.Binary + "_" + r.Module + "@" + r.Version }

func (r *ScanRequest) Path() string { return r.ModuleURLPath.Path() }

func (r *ScanRequest) Params() string {
	return scan.FormatParams(r.ScanParams)
}

func ParseScanRequest(r *http.Request, prefix string) (*ScanRequest, error) {
	mp, err := scan.ParseModuleURLPath(strings.TrimPrefix(r.URL.Path, prefix))
	if err != nil {
		return nil, err
	}

	ap := ScanParams{}
	if err := scan.ParseParams(r, &ap); err != nil {
		return nil, err
	}
	return &ScanRequest{
		ModuleURLPath: mp,
		ScanParams:    ap,
	}, nil
}

// These structs were copied, with minor changes, from
// golang.org/x/tools/go/analysis/internal/analysisflags.

// A JSONTree is a mapping from package ID to analysis name to result.
// Each result is either a jsonError or a list of JSONDiagnostic.
type JSONTree map[string]map[string]DiagnosticsOrError

// A JSONDiagnostic can be used to encode and decode
// analysis.Diagnostics to and from JSON.
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

// A JSONTextEdit describes the replacement of a portion of a file.
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

type DiagnosticsOrError struct {
	Diagnostics []JSONDiagnostic
	Error       *jsonError
}

func (de *DiagnosticsOrError) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &de.Diagnostics); err == nil {
		return nil
	}
	return json.Unmarshal(data, &de.Error)
}

// Definitions for BigQuery.

const TableName = "analysis"

// Note: before modifying AnalysisResult, make sure the change
// is a valid schema modification.
// The only supported changes are:
//   - adding a nullable or repeated column
//   - dropping a column
//   - changing a column from required to nullable.
// See https://cloud.google.com/bigquery/docs/managing-table-schemas for details.

// Result is a row in the BigQuery analysis table. It corresponds to a
// result from the output for an analysis.
type Result struct {
	CreatedAt   time.Time `bigquery:"created_at"`
	ModulePath  string    `bigquery:"module_path"`
	Version     string    `bigquery:"version"`
	SortVersion string    `bigquery:"sort_version"`
	CommitTime  time.Time `bigquery:"commit_time"`
	// The name of the analysis binary that was executed.
	// A single binary may run multiple analyzers.
	BinaryName    string `bigquery:"binary_name"`
	Error         string `bigquery:"error"`
	ErrorCategory string `bigquery:"error_category"`
	WorkVersion          // InferSchema flattens embedded fields

	Diagnostics []*Diagnostic `bigquery:"diagnostic"`
}

func (r *Result) AddError(err error) {
	if err == nil {
		return
	}
	r.Error = err.Error()
	r.ErrorCategory = derrors.CategorizeError(err)
}

func (r *Result) SetUploadTime(t time.Time) { r.CreatedAt = t }

// WorkVersion contains information that can be used to avoid duplicate work.
// Given two WorkVersion values v1 and v2 for the same module path and version,
// if v1 == v2 then it is not necessary to scan the module.
type WorkVersion struct {
	// A hash of the  binary executed.
	BinaryVersion string `bigquery:"binary_version"`
	BinaryArgs    string `bigquery:"binary_args"` // args passed to binary
	// The version of the currently running code. This tracks changes in the
	// logic of module scanning and processing.
	WorkerVersion string `bigquery:"worker_version"`
	// The version of the bigquery schema.
	SchemaVersion string ` bigquery:"schema_version"`
}

// A Diagnostic is a single analyzer finding.
type Diagnostic struct {
	// The package ID as reported by the analysis binary.
	PackageID    string `bigquery:"package_id"`
	AnalyzerName string `bigquery:"analyzer_name"`
	Error        string `bigquery:"error"`
	// These fields are from internal/worker.JSONDiagnostic.
	Category string        `bigquery:"category"`
	Position string        `bigquery:"position"`
	Message  string        `bigquery:"message"`
	Source   bq.NullString `bigquery:"source"`
}

// SchemaVersion changes whenever the analysis schema changes.
var SchemaVersion string

func init() {
	s, err := bigquery.InferSchema(Result{})
	if err != nil {
		panic(err)
	}
	SchemaVersion = bigquery.SchemaVersion(s)
	bigquery.AddTable(TableName, s)
}

// WorkVersionKey is the key for a WorkVersion.
// Always compare two WorkVersions with the same key.
type WorkVersionKey struct {
	Module  string
	Version string
	Binary  string
}

// ReadWorkVersions reads the most recent WorkVersions in the analysis table.
func ReadWorkVersions(ctx context.Context, c *bigquery.Client) (_ map[WorkVersionKey]WorkVersion, err error) {
	defer derrors.Wrap(&err, "ReadWorkVersions")
	m := map[WorkVersionKey]WorkVersion{}
	query := bigquery.PartitionQuery{
		Table:       c.FullTableName(TableName),
		Columns:     "module_path, version, binary_name, binary_version, binary_args, worker_version, schema_version",
		PartitionOn: "module_path, sort_version, binary_name",
		OrderBy:     "created_at DESC",
	}.String()
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	err = bigquery.ForEachRow(iter, func(r *Result) bool {
		m[WorkVersionKey{r.ModulePath, r.Version, r.BinaryName}] = r.WorkVersion
		return true
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// JSONTreeToDiagnostics converts a jsonTree to a list of diagnostics for BigQuery.
// It ignores the suggested fixes of the diagnostics.
func JSONTreeToDiagnostics(jsonTree JSONTree) []*Diagnostic {
	var diags []*Diagnostic
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
				diags = append(diags, &Diagnostic{
					PackageID:    pkgID,
					AnalyzerName: aName,
					Error:        diagsOrErr.Error.Err,
				})
			} else {
				for _, jd := range diagsOrErr.Diagnostics {
					diags = append(diags, &Diagnostic{
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
