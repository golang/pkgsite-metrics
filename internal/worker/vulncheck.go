// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"

	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
)

type VulncheckServer struct {
	*Server
	storedWorkVersions map[[2]string]*bigquery.VulncheckWorkVersion
	workVersion        *bigquery.VulncheckWorkVersion
}

func newVulncheckServer(ctx context.Context, s *Server) (*VulncheckServer, error) {
	var (
		swv map[[2]string]*bigquery.VulncheckWorkVersion
		err error
	)
	if s.bqClient != nil {
		swv, err = bigquery.ReadVulncheckWorkVersions(ctx, s.bqClient)
		if err != nil {
			return nil, err
		}
		log.Infof(ctx, "read %d work versions", len(swv))
	}
	return &VulncheckServer{
		Server:             s,
		storedWorkVersions: swv,
	}, nil
}

func (h *VulncheckServer) getWorkVersion(ctx context.Context) (_ *bigquery.VulncheckWorkVersion, err error) {
	defer derrors.Wrap(&err, "VulncheckServer.getWorkVersion")
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.workVersion == nil {
		lmt, err := h.vulndbClient.LastModifiedTime(ctx)
		if err != nil {
			return nil, err
		}
		vulnVersion, err := readVulnVersion()
		if err != nil {
			return nil, err
		}
		h.workVersion = &bigquery.VulncheckWorkVersion{
			VulnDBLastModified: lmt,
			WorkerVersion:      h.cfg.VersionID,
			SchemaVersion:      bigquery.VulncheckSchemaVersion,
			VulnVersion:        vulnVersion,
		}
		log.Infof(ctx, "vulncheck work version: %+v", h.workVersion)
	}
	return h.workVersion, nil
}

// readVulnVersion returns the version of the golang.org/x/vuln module linked into
// the current binary.
func readVulnVersion() (string, error) {
	const modulePath = "golang.org/x/vuln"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("vuln version not available")
	}
	for _, mod := range info.Deps {
		if mod.Path == modulePath {
			if mod.Replace != nil {
				mod = mod.Replace
			}
			return mod.Version, nil
		}
	}
	return "", fmt.Errorf("module %s not found", modulePath)
}

func (h *VulncheckServer) handlePage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	page, err := h.createVulncheckPage(ctx)
	if err != nil {
		return err
	}
	tmpl, err := h.Server.maybeLoadTemplate(vulncheckTemplate)
	if err != nil {
		return err
	}
	return renderPage(ctx, w, page, tmpl)
}

func (h *VulncheckServer) createVulncheckPage(ctx context.Context) (*VulncheckPage, error) {
	if h.bqClient == nil {
		return nil, errBQDisabled
	}
	table := h.bqClient.FullTableName(bigquery.VulncheckTableName)
	page := newPage(table)
	page.basePage = newBasePage()

	rows, err := bigquery.FetchVulncheckResults(ctx, h.bqClient)
	if err != nil {
		return nil, err
	}

	vulnsScanned := handleVulncheckRows(ctx, page, rows)
	page.NumVulnsScanned = len(vulnsScanned)
	page.addErrors()
	return page, nil
}

type VulncheckPage struct {
	basePage

	TableName string

	NumVulnsInDatabase int
	NumVulnsScanned    int

	VTAResult       *VulncheckResult
	VTAStacksResult *VulncheckResult
	ImportsResult   *VulncheckResult

	Errors []*ErrorCategory
}

type ErrorCategory struct {
	Name              string
	VTANumModules     int
	ImportsNumModules int
}

func (p *VulncheckPage) PercentVulnsScanned() float64 {
	return (float64(p.NumVulnsScanned) / float64(p.NumVulnsInDatabase)) * 100
}

func (p *VulncheckPage) NumModulesSuccess() int {
	return p.VTAResult.NumModulesSuccess + p.ImportsResult.NumModulesSuccess
}

type VulncheckResult struct {
	NumModulesScanned int
	NumModulesSuccess int
	NumModulesError   int
	NumModulesVuln    int

	ErrorCategory map[string]int

	maxScanSeconds float64
	sumScanSeconds float64

	maxScanMemory float64
	sumScanMemory float64
}

func (v *VulncheckResult) AverageScanSeconds() float64 {
	return v.sumScanSeconds / float64(v.NumModulesSuccess)
}

func (v *VulncheckResult) MaxScanSeconds() float64 {
	return v.maxScanSeconds
}

// AverageScanMemory in megabytes.
func (v *VulncheckResult) AverageScanMemory() float64 {
	return v.sumScanMemory / (float64(v.NumModulesSuccess) * 1024 * 1024)
}

// MaxScanMemory in megabytes.
func (v *VulncheckResult) MaxScanMemory() float64 {
	return v.maxScanMemory / (1024 * 1024)
}

func (v *VulncheckResult) NumModulesNoVuln() int {
	return v.NumModulesSuccess - v.NumModulesVuln
}

func (v *VulncheckResult) PercentSuccess() float64 {
	return (float64(v.NumModulesSuccess) / float64(v.NumModulesScanned)) * 100
}

func (v *VulncheckResult) PercentFailed() float64 {
	return (float64(v.NumModulesError) / float64(v.NumModulesScanned)) * 100
}

func (v *VulncheckResult) PercentVuln() float64 {
	return (float64(v.NumModulesVuln) / float64(v.NumModulesSuccess)) * 100
}

func (v *VulncheckResult) PercentNoVuln() float64 {
	return (float64(v.NumModulesNoVuln()) / float64(v.NumModulesSuccess)) * 100
}

func (r *VulncheckResult) update(row *bigquery.VulnResult) {
	r.NumModulesScanned++
	if row.Error != "" {
		r.NumModulesError++
		r.ErrorCategory[row.ErrorCategory]++
		return
	}
	r.NumModulesSuccess++

	s := row.ScanSeconds
	if s > r.maxScanSeconds {
		r.maxScanSeconds = s
	}
	r.sumScanSeconds += s

	m := float64(row.ScanMemory)
	if m > r.maxScanMemory {
		r.maxScanMemory = m
	}
	r.sumScanMemory += m

	if len(row.Vulns) > 0 {
		if row.ScanMode == ModeImports {
			r.NumModulesVuln++
		} else {
			// VTA and VTA with stacks mode.
			for _, v := range row.Vulns {
				if v.CallSink.Int64 > 0 {
					r.NumModulesVuln++
					break
				}
			}
		}
	}
}

// ReportResults contains aggregate results for a
// vulnerability reports, such as number of modules
// in which the vulnerability is found by vulncheck.
type ReportResult struct {
	VTANumModules     int
	ImportsNumModules int
}

// handleVulncheckRows populates page based on vulncheck result rows and
// returns statistics for each vulnerability detected.
func handleVulncheckRows(ctx context.Context, page *VulncheckPage, rows []*bigquery.VulnResult) map[string]*ReportResult {
	vulnsScanned := map[string]*ReportResult{}
	for _, row := range rows {
		switch row.ScanMode {
		case ModeVTA:
			page.VTAResult.update(row)
		case ModeVTAStacks:
			page.VTAStacksResult.update(row)
		case ModeImports:
			page.ImportsResult.update(row)
		default:
			log.Errorf(ctx, "unexpected mode for %s@%s: %q", row.ModulePath, row.Version, row.ScanMode)
			continue
		}

		// For each vuln, count the number of modules in which it
		// was detected for each mode. Since a vuln in row.Vulns
		// is defined by a symbol, make sure not to count multiple
		// symbols of each vuln separately.
		importsSeen := make(map[string]bool)
		callsSeen := make(map[string]bool)
		for _, v := range row.Vulns {
			if _, ok := vulnsScanned[v.ID]; !ok {
				vulnsScanned[v.ID] = &ReportResult{}
			}
			r := vulnsScanned[v.ID]

			if row.ScanMode == ModeImports {
				if !importsSeen[v.ID] {
					r.ImportsNumModules++
				}
				importsSeen[v.ID] = true
			}

			if row.ScanMode == ModeVTA && v.CallSink.Int64 > 0 {
				if !callsSeen[v.ID] {
					r.VTANumModules++
				}
				callsSeen[v.ID] = true
			}
		}
	}
	return vulnsScanned
}

func newPage(table string) *VulncheckPage {
	return &VulncheckPage{
		TableName:       table,
		VTAResult:       &VulncheckResult{ErrorCategory: make(map[string]int)},
		VTAStacksResult: &VulncheckResult{ErrorCategory: make(map[string]int)},
		ImportsResult:   &VulncheckResult{ErrorCategory: make(map[string]int)},
	}
}

func (page *VulncheckPage) addErrors() {
	ecs := map[string]*ErrorCategory{}
	for category, count := range page.VTAResult.ErrorCategory {
		if _, ok := ecs[category]; !ok {
			ecs[category] = &ErrorCategory{Name: category}
		}
		ecs[category].VTANumModules = count
	}
	for category, count := range page.ImportsResult.ErrorCategory {
		if _, ok := ecs[category]; !ok {
			ecs[category] = &ErrorCategory{Name: category}
		}
		ecs[category].ImportsNumModules = count
	}
	for _, ec := range ecs {
		page.Errors = append(page.Errors, ec)
	}
}
