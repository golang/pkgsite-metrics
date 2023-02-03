// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

import (
	"context"
	"fmt"
	"sort"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"golang.org/x/exp/maps"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"google.golang.org/api/iterator"
)

const VulncheckTableName = "vulncheck"

// Note: before modifying VulnResult or Vuln, make sure the change
// is a valid schema modification.
// The only supported changes are:
//   - adding a nullable or repeated column
//   - dropping a column
//   - changing a column from required to nullable.
// See https://cloud.google.com/bigquery/docs/managing-table-schemas for details.

// VulnResult is a row in the BigQuery vulncheck table. It corresponds to a
// result from the output for vulncheck.Source.
type VulnResult struct {
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
	Workers              int     `bigquery:"workers"`
	VulncheckWorkVersion         // InferSchema flattens embedded fields
	Vulns                []*Vuln `bigquery:"vulns"`
}

// VulncheckWorkVersion contains information that can be used to avoid duplicate work.
// Given two VulncheckWorkVersion values v1 and v2 for the same module path and version,
// if v1.Equal(v2) then it is not necessary to scan the module.
type VulncheckWorkVersion struct {
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

func (v1 *VulncheckWorkVersion) Equal(v2 *VulncheckWorkVersion) bool {
	if v1 == nil || v2 == nil {
		return v1 == v2
	}
	return v1.WorkerVersion == v2.WorkerVersion &&
		v1.SchemaVersion == v2.SchemaVersion &&
		v1.VulnVersion == v2.VulnVersion &&
		v1.VulnDBLastModified.Equal(v2.VulnDBLastModified)
}

func (vr *VulnResult) SetUploadTime(t time.Time) { vr.CreatedAt = t }

func (vr *VulnResult) AddError(err error) {
	if err == nil {
		return
	}
	vr.Error = err.Error()
	vr.ErrorCategory = derrors.CategorizeError(err)
}

// Vuln is a record in VulnResult and corresponds to an item in
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

// VulncheckSchemaVersion changes whenever the vulncheck schema changes.
var VulncheckSchemaVersion string

func init() {
	s, err := bq.InferSchema(VulnResult{})
	if err != nil {
		panic(err)
	}
	VulncheckSchemaVersion = schemaVersion(s)
	addTable(VulncheckTableName, s)
}

// ReadVulncheckWorkVersions reads the most recent WorkVersions in the vulncheck table.
func ReadVulncheckWorkVersions(ctx context.Context, c *Client) (_ map[[2]string]*VulncheckWorkVersion, err error) {
	defer derrors.Wrap(&err, "ReadVulncheckWorkVersions")
	m := map[[2]string]*VulncheckWorkVersion{}
	query := partitionQuery(c.FullTableName(VulncheckTableName), "module_path, sort_version", "created_at DESC")
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	err = ForEachRow(iter, func(r *VulnResult) bool {
		m[[2]string{r.ModulePath, r.Version}] = &r.VulncheckWorkVersion
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

func FetchVulncheckResults(ctx context.Context, c *Client) (rows []*VulnResult, err error) {
	return fetchVulncheckResults(ctx, c, VulncheckTableName)
}

func fetchVulncheckResults(ctx context.Context, c *Client, tableName string) (rows []*VulnResult, err error) {
	name := c.FullTableName(tableName)
	query := partitionQuery(name, "module_path, scan_mode", orderByClauses)
	log.Infof(ctx, "running latest query on %s", name)
	iter, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	rows, err = All[VulnResult](iter)
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

type ReportVulnResult struct {
	*VulnResult
	ReportDate civil.Date `bigquery:"report_date"` // for reporting (e.g. dashboard)
	InsertedAt time.Time  `bigquery:"inserted_at"` // to disambiguate if >1 insertion for same date
}

func init() {
	s, err := bq.InferSchema(ReportVulnResult{})
	if err != nil {
		panic(err)
	}
	addTable(VulncheckTableName+"-report", s)
}

func InsertVulncheckResults(ctx context.Context, c *Client, results []*VulnResult, date civil.Date, allowDuplicates bool) (err error) {
	return insertVulncheckResults(ctx, c, VulncheckTableName+"-report", results, date, allowDuplicates)
}

func insertVulncheckResults(ctx context.Context, c *Client, reportTableName string, results []*VulnResult, date civil.Date, allowDuplicates bool) (err error) {
	derrors.Wrap(&err, "InsertVulncheckResults(%s)", date)
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
	var rows []ReportVulnResult
	for _, r := range results {
		rows = append(rows, ReportVulnResult{VulnResult: r, ReportDate: date, InsertedAt: now})
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute) // to avoid retrying forever on permanent errors
	defer cancel()
	const chunkSize = 1024 // Chunk rows to a void exceeding the maximum allowable request size.
	return UploadMany(ctx, c, reportTableName, rows, chunkSize)
}
