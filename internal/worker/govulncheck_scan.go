// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/fstore"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/version"
)

const (
	// ModeGovulncheck is an ecosystem metrics mode that runs the govulncheck
	// binary in default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"

	// ModeCompare is an ecosystem metrics mode that finds compilable binaries
	// and runs govulncheck in both source and binary mode and reports results.
	ModeCompare = "COMPARE"
)

// modes is a set of supported govulncheck ecosystem metrics modes.
var modes = map[string]bool{
	ModeGovulncheck: true,
	ModeCompare:     true,
}

const (
	// scanModeSourceSymbol is used to designate results at govulncheck source
	// '-scan symbol' level of precision.
	//
	// Note that this is not an ecosystem metrics mode. Its value is "GOVULNCHECK"
	// for historical reasons.
	scanModeSourceSymbol = "GOVULNCHECK"

	// scanModeSourcePackage is used to designate results at govulncheck source
	// '-scan package' level of precision.
	//
	// Note that this is not an ecosystem metrics mode.
	scanModeSourcePackage string = "IMPORTS"

	// scanModeSourceModule is used to designate results at govulncheck source
	// '-scan module' level of precision.
	//
	// Note that this is not an ecosystem metrics mode.
	scanModeSourceModule string = "REQUIRES"

	// scanModeBinarySymbol is used to designate results at govulncheck binary
	// '-scan symbol' level of precision.
	//
	// Note that this is not an ecosystem metrics mode. Its value is "BINARY"
	// for historical reasons.
	scanModeBinarySymbol string = "BINARY"

	// sandboxGoCache is the location of the Go cache inside the sandbox. The
	// user is root and their $HOME directory is /root. The Go cache resides
	// in its default location, $HOME/.cache/go-build.
	sandboxGoCache = "root/.cache/go-build"
)

func modeToGovulncheckFlag(mode string) string {
	switch mode {
	case scanModeBinarySymbol:
		return govulncheck.FlagBinary
	default:
		return govulncheck.FlagSource
	}
}

var (
	// gReqCounter counts requests to govulncheck handleScan
	gReqCounter = event.NewCounter("govulncheck-requests", &event.MetricOptions{Namespace: metricNamespace})
	// gSuccCounter counts successfully processed requests to govulncheck handleScan
	gSuccCounter = event.NewCounter("govulncheck-requests-ok", &event.MetricOptions{Namespace: metricNamespace})
	// gSkipCounter counts skipped requests to govulncheck handleScan
	gSkipCounter = event.NewCounter("govulncheck-requests-skip", &event.MetricOptions{Namespace: metricNamespace})
)

// handleScan runs a govulncheck scan for a single input module. It is triggered
// by path /govulncheck/scan/MODULE_VERSION_SUFFIX?params.
//
// See internal/govulncheck.ParseRequest for allowed path forms and query params.
func (h *GovulncheckServer) handleScan(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "handleScan")

	// Collect basic metrics.
	gReqCounter.Record(r.Context(), 1)
	skip := false // request skipped
	defer func() {
		gSuccCounter.Record(r.Context(), 1, event.Bool("success", err == nil))
		gSkipCounter.Record(r.Context(), 1, event.Bool("skipped", skip))
	}()

	ctx := r.Context()
	sreq, err := govulncheck.ParseRequest(r, "/govulncheck/scan")
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	if sreq.Mode == "" {
		sreq.Mode = ModeGovulncheck
	}
	scanner, err := newScanner(ctx, h)
	if err != nil {
		return err
	}
	// An explicit "insecure" query param overrides the default.
	if sreq.Insecure {
		scanner.insecure = sreq.Insecure
	}
	skip, err = scanner.canSkip(ctx, sreq, h.fsNamespace)
	if err != nil {
		return err
	}
	if skip {
		log.Infof(ctx, "skipping (work version unchanged or unrecoverable error): %s@%s", sreq.Module, sreq.Version)
		return nil
	}
	workState, err := scanner.ScanModule(ctx, w, sreq)
	if err != nil {
		return err
	}
	if workState == nil {
		return nil
	}
	// We can't upload the row to bigquery and write the WorkState to Firestore atomically.
	// But that's OK: if we fail before writing the WorkState, then we'll just re-do the scan
	// the next time.
	if err := govulncheck.SetWorkState(ctx, h.fsNamespace, sreq.Module, sreq.Version, workState); err != nil {
		// Don't fail if there's an error, because we'd just re-run the task.
		log.Errorf(ctx, err, "SetWorkState")
	}
	return nil
}

func (s *scanner) canSkip(ctx context.Context, sreq *govulncheck.Request, fsn *fstore.Namespace) (bool, error) {
	ws, err := govulncheck.GetWorkState(ctx, fsn, sreq.Module, sreq.Version)
	if err != nil {
		return false, err
	}
	if ws == nil {
		// Not scanned before.
		return false, nil
	}
	log.Infof(ctx, "read work version for %s@%s", sreq.Module, sreq.Version)
	if s.workVersion.Equal(ws.WorkVersion) {
		// If the work version has not changed, skip analyzing the module
		return true, nil
	}
	// Otherwise, skip if the error is not recoverable. The version of the
	// module has not changed, so we'll get the same error anyhow.
	return unrecoverableError(ws.ErrorCategory), nil
}

// unrecoverableError returns true iff errorCategory encodes that
// the project has an error that is unrecoverable from the perspective
// of govulncheck. One example is build issues.
func unrecoverableError(errorCategory string) bool {
	switch errorCategory {
	case derrors.CategorizeError(derrors.LoadPackagesError): // We model build issues as a general load error.
		return true
	default:
		return false
	}
}

// A scanner holds state for scanning modules.
type scanner struct {
	proxyClient *proxy.Client
	bqClient    *bigquery.Client
	workVersion *govulncheck.WorkVersion
	gcsBucket   *storage.BucketHandle
	insecure    bool
	sbox        *sandbox.Sandbox
	binaryDir   string

	govulncheckPath string
	vulnDBDir       string
}

func newScanner(ctx context.Context, h *GovulncheckServer) (*scanner, error) {
	workVersion, err := h.getWorkVersion(ctx)
	if err != nil {
		return nil, err
	}
	var bucket *storage.BucketHandle
	if h.cfg.BinaryBucket != "" {
		c, err := storage.NewClient(ctx)
		if err != nil {
			return nil, err
		}
		bucket = c.Bucket(h.cfg.BinaryBucket)
	}
	sbox := sandbox.New("/bundle")
	sbox.Runsc = "/usr/local/bin/runsc"
	return &scanner{
		proxyClient:     h.proxyClient,
		bqClient:        h.bqClient,
		workVersion:     workVersion,
		gcsBucket:       bucket,
		insecure:        h.cfg.Insecure,
		sbox:            sbox,
		binaryDir:       h.cfg.BinaryDir,
		govulncheckPath: filepath.Join(h.cfg.BinaryDir, "govulncheck"),
		vulnDBDir:       h.cfg.VulnDBDir,
	}, nil
}

type scanError struct {
	err error
}

func (s scanError) Error() string {
	return s.err.Error()
}

func (s scanError) Unwrap() error {
	return s.err
}

// CompareModule gets results of govulncheck source and binary mode on each binary defined in a module.
//
// It discards all results where there is a failure that is not specific to the comparison. Examples are
// situations where the module is malformed, govulncheck fails, or it is not possible to build a found
// binary within the module.
func (s *scanner) CompareModule(ctx context.Context, w http.ResponseWriter, sreq *govulncheck.Request, info *proxy.VersionInfo, baseRow *govulncheck.Result) (err error) {
	defer derrors.Wrap(&err, "CompareModule")
	err = doScan(ctx, baseRow.ModulePath, info.Version, s.insecure, func() (err error) {
		inputPath := moduleDir(baseRow.ModulePath, info.Version)
		defer derrors.Cleanup(&err, func() error { return os.RemoveAll(inputPath) })
		const init = true
		if err := prepareModule(ctx, baseRow.ModulePath, info.Version, inputPath, s.proxyClient, s.insecure, init); err != nil {
			log.Errorf(ctx, err, "error trying to prepare module %s", baseRow.ModulePath)
			return nil
		}

		smdir := strings.TrimPrefix(inputPath, sandboxRoot)
		err = s.sbox.Validate()
		log.Debugf(ctx, "sandbox Validate returned %v", err)

		response, err := s.runGovulncheckCompareSandbox(ctx, smdir)
		if err != nil {
			return err
		}
		log.Infof(ctx, "scanner.runGovulncheckCompare found %d compilable binaries in %s:", len(response.FindingsForMod), sreq.Path())

		var rows []bigquery.Row
		for pkg, results := range response.FindingsForMod {
			if results.Error != "" {
				// Just log error if binary failed to build or the analysis failed.
				// TODO: should we save those rows? This would complicate clients, namely the dashboards.
				log.Errorf(ctx, errors.New(results.Error), "building/analyzing binary failed: %s %s", pkg, sreq.Path())
				continue
			}

			binRow := createComparisonRow(pkg, &results.BinaryResults, baseRow, scanModeBinarySymbol)
			srcRow := createComparisonRow(pkg, &results.SourceResults, baseRow, scanModeSourceSymbol)
			log.Infof(ctx, "found %d vulns in binary mode and %d vulns in source mode for package %s (module: %s)", len(binRow.Vulns), len(srcRow.Vulns), pkg, sreq.Path())
			rows = append(rows, binRow, srcRow)
		}

		if len(rows) > 0 {
			return writeResults(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, rows)
		}
		return nil
	})

	if err != nil {
		log.Errorf(ctx, err, "CompareModule failed for: %s", baseRow.ModulePath)
	}
	return nil
}

func createComparisonRow(pkg string, result *govulncheck.SandboxResponse, baseRow *govulncheck.Result, scanMode string) (row *govulncheck.Result) {
	row = &govulncheck.Result{
		CreatedAt:   baseRow.CreatedAt,
		Suffix:      pkg,
		ModulePath:  baseRow.ModulePath,
		Version:     baseRow.Version,
		SortVersion: baseRow.SortVersion,
		ImportedBy:  baseRow.ImportedBy,
		CommitTime:  baseRow.CommitTime,
		WorkVersion: baseRow.WorkVersion,
	}
	if scanMode == scanModeBinarySymbol {
		row.ScanMode = "COMPARE - BINARY"
		row.BinaryBuildSeconds = bigquery.NullFloat(result.Stats.BuildTime.Seconds())
	} else {
		row.ScanMode = "COMPARE - SOURCE"
	}

	row.Vulns = vulnsForScanMode(result.Findings, scanMode)
	row.ScanMemory = int64(result.Stats.ScanMemory)
	row.ScanSeconds = result.Stats.ScanSeconds
	return row
}

// ScanModule scans the module in the request. It returns the WorkState for the result.
func (s *scanner) ScanModule(ctx context.Context, w http.ResponseWriter, sreq *govulncheck.Request) (*govulncheck.WorkState, error) {
	if sreq.Module == "std" {
		return nil, nil // ignore the standard library
	}
	// baseRow is used to return on a premature error and
	// to create actual bq rows otherwise.
	baseRow := &govulncheck.Result{
		ModulePath:  sreq.Module,
		Suffix:      sreq.Suffix,
		WorkVersion: *s.workVersion,
		ImportedBy:  sreq.ImportedBy,
	}
	baseRow.VulnDBLastModified = s.workVersion.VulnDBLastModified

	// Scan the version.
	log.Debugf(ctx, "fetching proxy info: %s@%s", sreq.Path(), sreq.Version)
	info, err := s.proxyClient.Info(ctx, sreq.Module, sreq.Version)
	if err != nil {
		log.Infof(ctx, "proxy error: %s@%s %v", sreq.Path(), sreq.Version, err)
		baseRow.AddError(fmt.Errorf("%v: %w", err, derrors.ProxyError))
		// If proxy failed, put the scan mode as the incoming ecosystem mode
		// for now.
		// TODO: is there a better way of doing this?
		baseRow.ScanMode = sreq.Mode
		if err := writeResult(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, baseRow); err != nil {
			return nil, err
		}
		return baseRow.WorkState(), nil
	}
	baseRow.Version = info.Version
	baseRow.SortVersion = version.ForSorting(baseRow.Version)
	baseRow.CommitTime = info.Time

	if sreq.Mode == ModeCompare {
		err := s.CompareModule(ctx, w, sreq, info, baseRow)
		// TODO: WorkState for CompareModule requests?
		return nil, err
	}

	log.Infof(ctx, "running scanner.runScanModule: %s@%s", sreq.Path(), sreq.Version)
	stats := &govulncheck.ScanStats{}
	findings, err := s.runScanModule(ctx, sreq.Module, info.Version, sreq.Mode, stats)
	baseRow.ScanSeconds = stats.ScanSeconds
	baseRow.ScanMemory = int64(stats.ScanMemory)
	if err != nil {
		switch {
		case isGovulncheckLoadError(err) || isBuildIssue(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesError)
		case isNoRequiredModule(err):
			// Should be subsumed by LoadPackagesError, kept for sanity
			// and to catch unexpected changes in govulncheck output.
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoRequiredModuleError)
		case isMissingGoSumEntry(err):
			// Should be subsumed by LoadPackagesError, kept for sanity.
			// and to catch unexpected changes in govulncheck output.
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesMissingGoSumEntryError)
		case isReplacingWithLocalPath(err):
			// Should be subsumed by LoadPackagesError, kept for sanity.
			// and to catch unexpected changes in govulncheck output.
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesImportedLocalError)
		case isModVendor(err):
			// Should be subsumed by LoadPackagesError, kept for sanity.
			// and to catch unexpected changes in govulncheck output.
			err = fmt.Errorf("%v: %w", err, derrors.LoadVendorError)
		case isMissingGoMod(err) || isNoModulesSpecified(err):
			// Should be subsumed by LoadPackagesError, kept for sanity
			// and to catch unexpected changes in govulncheck output.
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoModError)
		case isTooManyFiles(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleTooManyOpenFiles)
		case isProxyCacheMiss(err):
			err = fmt.Errorf("%v: %w", err, derrors.ProxyError)
		case isSandboxRelatedIssue(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleSandboxError)
		default:
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleGovulncheckError)
		}
		baseRow.AddError(err)
	}

	// create a row for each precision level
	var rows []bigquery.Row
	for _, mode := range []string{scanModeSourceSymbol, scanModeSourcePackage, scanModeSourceModule} {
		row := *baseRow
		row.ScanMode = mode
		// We use govulncheck command execution time as the approx. time for symbol level analysis.
		// We currently don't have a way of approximating time for measuring time for module and
		// package level scans. We could run govulncheck with -scan package and -scan module, but
		// that would put more pressure on the pipeline and use more resources.
		// TODO: could we instrument handler to measure this for us?
		if mode != ModeGovulncheck {
			row.ScanSeconds = 0
			row.ScanMemory = 0
		}
		row.Vulns = vulnsForScanMode(findings, mode)
		log.Infof(ctx, "scanner.runScanModule returned %d findings and err=%v for %s with row.Vulns=%d in scan mode=%s", len(findings), err, sreq.Path(), len(row.Vulns), mode)
		rows = append(rows, &row)
	}
	if err := writeResults(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, rows); err != nil {
		return nil, err
	}
	return baseRow.WorkState(), nil
}

// vulnsForScanMode produces Vulns from findings at the specified
// govulncheck scan mode.
func vulnsForScanMode(findings []*govulncheckapi.Finding, mode string) []*govulncheck.Vuln {
	var modeFindings []*govulncheckapi.Finding
	for _, f := range findings {
		fr := f.Trace[0]
		switch mode {
		case scanModeSourceSymbol, scanModeBinarySymbol:
			if fr.Function != "" {
				modeFindings = append(modeFindings, f)
			}
		case scanModeSourcePackage:
			if fr.Package != "" && fr.Function == "" {
				modeFindings = append(modeFindings, f)
			}
		case scanModeSourceModule:
			if fr.Package == "" && fr.Function == "" { // fr.Module is always set
				modeFindings = append(modeFindings, f)
			}
		}
	}

	var vulns []*govulncheck.Vuln
	seen := make(map[govulncheck.Vuln]bool) // avoid duplicates
	for _, f := range modeFindings {
		v := govulncheck.ConvertGovulncheckFinding(f)
		if seen[*v] {
			continue
		}
		seen[*v] = true
		vulns = append(vulns, v)
	}
	return vulns
}

// runScanModule fetches the module version from the proxy, and analyzes its source
// code for vulnerabilities. The analysis of binaries is done in CompareModules.
func (s *scanner) runScanModule(ctx context.Context, modulePath, version, mode string, stats *govulncheck.ScanStats) (findings []*govulncheckapi.Finding, err error) {
	err = doScan(ctx, modulePath, version, s.insecure, func() (err error) {
		// Download the module first.
		inputPath := moduleDir(modulePath, version)
		defer derrors.Cleanup(&err, func() error { return os.RemoveAll(inputPath) })
		const init = true
		if err := prepareModule(ctx, modulePath, version, inputPath, s.proxyClient, s.insecure, init); err != nil {
			return err
		}

		if s.insecure {
			findings, err = s.runGovulncheckScanInsecure(inputPath, mode, stats)
		} else {
			findings, err = s.runGovulncheckScanSandbox(ctx, inputPath, mode, stats)
		}
		log.Debugf(ctx, "govulncheck stats: %dkb | %vs", stats.ScanMemory, stats.ScanSeconds)
		return err
	})
	return findings, err
}

func (s *scanner) runGovulncheckScanSandbox(ctx context.Context, inputPath, mode string, stats *govulncheck.ScanStats) (_ []*govulncheckapi.Finding, err error) {
	smdir := strings.TrimPrefix(inputPath, sandboxRoot)
	err = s.sbox.Validate()
	log.Debugf(ctx, "sandbox Validate returned %v", err)

	response, err := s.runGovulncheckSandbox(ctx, mode, smdir)
	if err != nil {
		return nil, err
	}
	stats.ScanMemory = response.Stats.ScanMemory
	stats.ScanSeconds = response.Stats.ScanSeconds
	return response.Findings, nil
}

func (s *scanner) runGovulncheckSandbox(ctx context.Context, mode, arg string) (*govulncheck.SandboxResponse, error) {
	goOut, err := s.sbox.Command("/usr/local/go/bin/go", "version").Output()
	if err != nil {
		log.Debugf(ctx, "running go version error: %v", err)
	} else {
		log.Debugf(ctx, "Sandbox running %s", goOut)
	}
	log.Infof(ctx, "running govulncheck in sandbox: mode %s, arg %q", mode, arg)
	cmd := s.sbox.Command(filepath.Join(s.binaryDir, "govulncheck_sandbox"), s.govulncheckPath, modeToGovulncheckFlag(mode), arg, s.vulnDBDir)
	stdout, err := cmd.Output()
	log.Infof(ctx, "govulncheck in sandbox finished with err=%v", err)
	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	return govulncheck.UnmarshalSandboxResponse(stdout)
}

func (s *scanner) runGovulncheckCompareSandbox(ctx context.Context, arg string) (*govulncheck.CompareResponse, error) {
	cmd := s.sbox.Command(filepath.Join(s.binaryDir, "govulncheck_compare"), s.govulncheckPath, arg, s.vulnDBDir)
	log.Infof(ctx, "running govulncheck_compare: arg %q", arg)
	stdout, err := cmd.Output()
	log.Infof(ctx, "govulncheck_compare in sandbox finished with err=%v", err)
	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	return govulncheck.UnmarshalCompareResponse(stdout)
}

func (s *scanner) runGovulncheckScanInsecure(inputPath, mode string, stats *govulncheck.ScanStats) (_ []*govulncheckapi.Finding, err error) {
	return govulncheck.RunGovulncheckCmd(s.govulncheckPath, modeToGovulncheckFlag(mode), "./...", inputPath, s.vulnDBDir, stats)
}

func isGovulncheckLoadError(err error) bool {
	return strings.Contains(err.Error(), "govulncheck: loading packages:") ||
		strings.Contains(err.Error(), "FindAndBuildBinaries")
}
