// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

import (
	"context"
	"time"

	bq "cloud.google.com/go/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
)

const AnalysisTableName = "analysis"

// Note: before modifying AnalysisResult, make sure the change
// is a valid schema modification.
// The only supported changes are:
//   - adding a nullable or repeated column
//   - dropping a column
//   - changing a column from required to nullable.
// See https://cloud.google.com/bigquery/docs/managing-table-schemas for details.

// AnalysisResult is a row in the BigQuery analysis table. It corresponds to a
// result from the output for an analysis.
type AnalysisResult struct {
	CreatedAt   time.Time `bigquery:"created_at"`
	ModulePath  string    `bigquery:"module_path"`
	Version     string    `bigquery:"version"`
	SortVersion string    `bigquery:"sort_version"`
	CommitTime  time.Time `bigquery:"commit_time"`
	// The name of the analysis binary that was executed.
	// A single binary may run multiple analyzers.
	BinaryName          string `bigquery:"binary_name"`
	Error               string `bigquery:"error"`
	ErrorCategory       string `bigquery:"error_category"`
	AnalysisWorkVersion        // InferSchema flattens embedded fields

	Diagnostics []*Diagnostic `bigquery:"diagnostic"`
}

func (r *AnalysisResult) AddError(err error) {
	if err == nil {
		return
	}
	r.Error = err.Error()
	r.ErrorCategory = derrors.CategorizeError(err)
}

// AnalysisWorkVersion contains information that can be used to avoid duplicate work.
// Given two AnalysisWorkVersion values v1 and v2 for the same module path and version,
// if v1 == v2 then it is not necessary to scan the module.
type AnalysisWorkVersion struct {
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
	Category string `bigquery:"category"`
	Position string `bigquery:"position"`
	Message  string `bigquery:"message"`
}

// AnalysisSchemaVersion changes whenever the analysis schema changes.
var AnalysisSchemaVersion string

func init() {
	s, err := bq.InferSchema(AnalysisResult{})
	if err != nil {
		panic(err)
	}
	AnalysisSchemaVersion = schemaVersion(s)
	addTable(AnalysisTableName, s)
}

// ReadAnalysisWorkVersions reads the most recent WorkVersions in the analysis table.
func ReadAnalysisWorkVersions(ctx context.Context, c *Client) (_ map[[2]string]*AnalysisWorkVersion, err error) {
	defer derrors.Wrap(&err, "ReadAnalysisWorkVersions")
	m := map[[2]string]*AnalysisWorkVersion{}
	query := partitionQuery(c.FullTableName(AnalysisTableName), "module_path, sort_version", "created_at DESC")
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	err = ForEachRow(iter, func(r *AnalysisResult) bool {
		m[[2]string{r.ModulePath, r.Version}] = &r.AnalysisWorkVersion
		return true
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}
