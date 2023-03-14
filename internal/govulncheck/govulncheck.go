// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"golang.org/x/exp/maps"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/scan"
	"golang.org/x/vuln/exp/govulncheck"
	"google.golang.org/api/iterator"
)

// EnqueueQueryParams for vulncheck/enqueue
type EnqueueQueryParams struct {
	Suffix string // appended to task queue IDs to generate unique tasks
	Mode   string // type of analysis to run
	Min    int    // minimum import-by count for a module to be included
	File   string // path to file containing modules; if missing, use DB
}

// Request contains information passed
// to a scan endpoint.
type Request struct {
	scan.ModuleURLPath
	QueryParams
}

// QueryParams has query parameters for a vulncheck scan request.
type QueryParams struct {
	ImportedBy int    // imported-by count
	Mode       string // vulncheck mode (VTA, etc)
	Insecure   bool   // if true, run outside sandbox
	Serve      bool   // serve results back to client instead of writing them to BigQuery
}

// These methods implement queue.Task.
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

func ConvertGovulncheckOutput(v *govulncheck.Vuln) (vulns []*Vuln) {
	for _, module := range v.Modules {
		for pkgNum, pkg := range module.Packages {
			addedSymbols := make(map[string]bool)
			baseVuln := &Vuln{
				ID:          v.OSV.ID,
				ModulePath:  module.Path,
				PackagePath: pkg.Path,
				CallSink:    bigquery.NullInt(0),
				ImportSink:  bigquery.NullInt(pkgNum + 1),
				RequireSink: bigquery.NullInt(pkgNum + 1),
			}

			// For each called symbol, reconstruct sinks and create the corresponding bigquery vuln
			for symbolNum, cs := range pkg.CallStacks {
				addedSymbols[cs.Symbol] = true
				toAdd := *baseVuln
				toAdd.Symbol = cs.Symbol
				toAdd.CallSink = bigquery.NullInt(symbolNum + 1)
				vulns = append(vulns, &toAdd)
			}

			// Find the rest of the vulnerable imported symbols that haven't been called
			// and create corresponding bigquery vulns
			for _, affected := range v.OSV.Affected {
				if affected.Package.Name == module.Path {
					for _, imp := range affected.EcosystemSpecific.Imports {
						if imp.Path == pkg.Path {
							for _, symbol := range imp.Symbols {
								if !addedSymbols[symbol] {
									toAdd := *baseVuln
									toAdd.Symbol = symbol
									vulns = append(vulns, &toAdd)
								}
							}
						}
					}
				}
			}
		}
	}
	return vulns
}

const TableName = "vulncheck"

// Note: before modifying Result or Vuln, make sure the change
// is a valid schema modification.
// The only supported changes are:
//   - adding a nullable or repeated column
//   - dropping a column
//   - changing a column from required to nullable.
// See https://cloud.google.com/bigquery/docs/managing-table-schemas for details.

// Result is a row in the BigQuery vulncheck table. It corresponds to a
// result from the output for vulncheck.Source.
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
	PkgsMemory    int64     `bigquery:"pkgs_memory"`
	ScanMode      string    `bigquery:"scan_mode"`
	// Workers is the concurrency limit under which a module is
	// analyzed. Useful for interpreting memory measurements when
	// there are multiple modules analyzed in the same process.
	// 0 if no limit is specified, -1 for potential errors.
	Workers     int     `bigquery:"workers"`
	WorkVersion         // InferSchema flattens embedded fields
	Vulns       []*Vuln `bigquery:"vulns"`
}

// WorkVersion contains information that can be used to avoid duplicate work.
// Given two WorkVersion values v1 and v2 for the same module path and version,
// if v1.Equal(v2) then it is not necessary to scan the module.
type WorkVersion struct {
	// The version of the currently running code. This tracks changes in the
	// logic of module scanning and processing.
	WorkerVersion string `bigquery:"worker_version"`
	// The version of the bigquery schema.
	SchemaVersion string ` bigquery:"schema_version"`
	// The version of the golang.org/x/vuln module used by the current module.
	VulnVersion string `bigquery:"x_vuln_version"`
	// When the vuln DB was last modified.
	VulnDBLastModified time.Time `bigquery:"vulndb_last_modified"`
}

func (v1 *WorkVersion) Equal(v2 *WorkVersion) bool {
	if v1 == nil || v2 == nil {
		return v1 == v2
	}
	return v1.WorkerVersion == v2.WorkerVersion &&
		v1.SchemaVersion == v2.SchemaVersion &&
		v1.VulnVersion == v2.VulnVersion &&
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

// Vuln is a record in Result and corresponds to an item in
// vulncheck.Result.Vulns.
type Vuln struct {
	ID          string       `bigquery:"id"`
	Symbol      string       `bigquery:"symbol"`
	PackagePath string       `bigquery:"package_path"`
	ModulePath  string       `bigquery:"module_path"`
	CallSink    bq.NullInt64 `bigquery:"call_sink"`
	ImportSink  bq.NullInt64 `bigquery:"import_sink"`
	RequireSink bq.NullInt64 `bigquery:"require_sink"`
}

// SchemaVersion changes whenever the vulncheck schema changes.
var SchemaVersion string

func init() {
	s, err := bigquery.InferSchema(Result{})
	if err != nil {
		panic(err)
	}
	SchemaVersion = bigquery.SchemaVersion(s)
	bigquery.AddTable(TableName, s)
}

// ReadWorkVersions reads the most recent WorkVersions in the vulncheck table.
func ReadWorkVersions(ctx context.Context, c *bigquery.Client) (_ map[[2]string]*WorkVersion, err error) {
	defer derrors.Wrap(&err, "ReadWorkVersions")
	m := map[[2]string]*WorkVersion{}
	query := bigquery.PartitionQuery{
		Table:       c.FullTableName(TableName),
		Columns:     "module_path, version, worker_version, schema_version, x_vuln_version, vulndb_last_modified",
		PartitionOn: "module_path, sort_version",
		OrderBy:     "created_at DESC",
	}.String()
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	err = bigquery.ForEachRow(iter, func(r *Result) bool {
		m[[2]string{r.ModulePath, r.Version}] = &r.WorkVersion
		return true
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// The module path along with the four sort columns should uniquely specify a
// row, because we do not generate a new row for a (module, version) if the
// other three versions are identical. (There is actually a fourth component of
// the work version, the schema version. But since it is represented by a struct
// in the worker code and the worker version captures every change to that code,
// it cannot change independently of worker_version.)
const orderByClauses = `
			vulndb_last_modified DESC, -- latest version of database
			x_vuln_version DESC,       -- latest version of x/vuln
			worker_version DESC,       -- latest version of x/pkgsite-metrics
			sort_version DESC,         -- latest version of module
			created_at DESC            -- latest insertion time
`

func FetchResults(ctx context.Context, c *bigquery.Client) (rows []*Result, err error) {
	return fetchResults(ctx, c, TableName)
}

func fetchResults(ctx context.Context, c *bigquery.Client, tableName string) (rows []*Result, err error) {
	name := c.FullTableName(tableName)
	query := bigquery.PartitionQuery{
		Table:       name,
		PartitionOn: "module_path, scan_mode",
		OrderBy:     orderByClauses,
	}.String()
	log.Infof(ctx, "running latest query on %s", name)
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	rows, err = bigquery.All[Result](iter)
	if err != nil {
		return nil, err
	}
	log.Infof(ctx, "got %d rows", len(rows))

	// Check for duplicate rows.
	modvers := map[string]int{}
	for _, r := range rows {
		modvers[r.ModulePath+"@"+r.Version+" "+r.ScanMode]++
	}
	keys := maps.Keys(modvers)
	sort.Strings(keys)
	for _, k := range keys {
		if n := modvers[k]; n > 1 {
			return nil, fmt.Errorf("%s has %d rows", k, n)
		}
	}
	return rows, nil
}

type ReportResult struct {
	*Result
	ReportDate civil.Date `bigquery:"report_date"` // for reporting (e.g. dashboard)
	InsertedAt time.Time  `bigquery:"inserted_at"` // to disambiguate if >1 insertion for same date
}

func init() {
	s, err := bigquery.InferSchema(ReportResult{})
	if err != nil {
		panic(err)
	}
	bigquery.AddTable(TableName+"-report", s)
}

func InsertResults(ctx context.Context, c *bigquery.Client, results []*Result, date civil.Date, allowDuplicates bool) (err error) {
	return insertResults(ctx, c, TableName+"-report", results, date, allowDuplicates)
}

func insertResults(ctx context.Context, c *bigquery.Client, reportTableName string, results []*Result, date civil.Date, allowDuplicates bool) (err error) {
	derrors.Wrap(&err, "InsertResults(%s)", date)
	// Create the report table if it doesn't exist.
	if err := c.CreateTable(ctx, reportTableName); err != nil {
		return err
	}

	if !allowDuplicates {
		query := fmt.Sprintf("SELECT COUNT(*) FROM `%s` WHERE report_date = '%s'",
			c.FullTableName(reportTableName), date)
		iter, err := c.Query(ctx, query)
		if err != nil {
			return err
		}
		var count struct {
			n int
		}
		err = iter.Next(&count)
		if err != nil && err != iterator.Done {
			return err
		}
		if count.n > 0 {
			return fmt.Errorf("already have %d rows for %s", count.n, date)
		}
	}

	now := time.Now()
	var rows []ReportResult
	for _, r := range results {
		rows = append(rows, ReportResult{Result: r, ReportDate: date, InsertedAt: now})
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute) // to avoid retrying forever on permanent errors
	defer cancel()
	const chunkSize = 1024 // Chunk rows to a void exceeding the maximum allowable request size.
	return bigquery.UploadMany(ctx, c, reportTableName, rows, chunkSize)
}

// ScanStats represent monitoring information about a given
// run of govulncheck or vulncheck
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
	Res   govulncheck.Result
	Stats ScanStats
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

func UnmarshalGovulncheckResult(output []byte) (*govulncheck.Result, error) {
	var e struct {
		Error string
	}
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res govulncheck.Result
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
