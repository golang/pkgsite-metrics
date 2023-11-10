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
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/govulncheckapi"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/version"
)

const (
	// modeImports is used to report results of vulnerability detection at
	// imports level precision. It cannot be directly triggered by scan
	// endpoints. Instead, ModeGovulncheck mode reports its results to show
	// difference in precision of vulnerability detection.
	modeImports string = "IMPORTS"

	// ModeGovulncheck runs the govulncheck binary in default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"

	// ModeCompare finds compilable binaries and runs govulncheck in both source
	// and binary mode.
	ModeCompare = "COMPARE"

	// modeBinary is only used by ModeCompare for reporting results. It cannot
	// be directly triggered by scan endpoints.
	modeBinary string = "BINARY"

	// sandboxGoCache is the location of the Go cache inside the sandbox. The
	// user is root and their $HOME directory is /root. The Go cache resides
	// in its default location, $HOME/.cache/go-build.
	sandboxGoCache = "root/.cache/go-build"
)

// modes is a set of govulncheck modes externally visible.
var modes = map[string]bool{
	ModeGovulncheck: true,
	ModeCompare:     true,
}

func modeToGovulncheckFlag(mode string) string {
	switch mode {
	case modeBinary: // for sanity
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
	h.Server.reqs++
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
	skip, err = h.canSkip(ctx, sreq, scanner)
	if err != nil {
		return err
	}
	if skip {
		log.Infof(ctx, "skipping (work version unchanged or unrecoverable error): %s@%s", sreq.Module, sreq.Version)
		return nil
	}

	return scanner.ScanModule(ctx, w, sreq)
}

func (h *GovulncheckServer) canSkip(ctx context.Context, sreq *govulncheck.Request, scanner *scanner) (bool, error) {
	if err := h.readGovulncheckWorkState(ctx, sreq.Module, sreq.Version); err != nil {
		return false, err
	}
	wve := h.storedWorkStates[[2]string{sreq.Module, sreq.Version}]
	if wve == nil {
		// sreq.Module@sreq.Version have not been analyzed before.
		return false, nil
	}

	if scanner.workVersion.Equal(wve.WorkVersion) {
		// If the work version has not changed, skip analyzing the module
		return true, nil
	}
	// Otherwise, skip if the error is not recoverable. The version of the
	// module has not changed, so we'll get the same error anyhow.
	return unrecoverableError(wve.ErrorCategory), nil
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

func (h *GovulncheckServer) readGovulncheckWorkState(ctx context.Context, module_path, version string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Don't read work state for module_path@version if an entry in the cache already exists.
	if _, ok := h.storedWorkStates[[2]string{module_path, version}]; ok {
		return nil
	}
	if h.bqClient == nil {
		return nil
	}
	ws, err := govulncheck.ReadWorkState(ctx, h.bqClient, module_path, version)
	if err != nil {
		return err
	}
	if ws != nil {
		h.storedWorkStates[[2]string{module_path, version}] = ws
	}
	log.Infof(ctx, "read work version for %s@%s", module_path, version)
	return nil
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
// It discards all results where there is a failure that is not specific to the comparison, i.e., failures
// that appear in GOVULNCHECK or IMPORTS mode. Examples are situations where the module is malformed,
// govulncheck fails, or it is not possible to build a found binary within the module.
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

			binRow := createComparisonRow(pkg, &results.BinaryResults, baseRow, modeBinary)
			srcRow := createComparisonRow(pkg, &results.SourceResults, baseRow, ModeGovulncheck)
			log.Infof(ctx, "found %d vulns in binary mode and %d vulns in source mode for package %s (module: %s)", len(binRow.Vulns), len(srcRow.Vulns), pkg, sreq.Path())
			rows = append(rows, binRow, srcRow)
		}

		if len(rows) > 0 {
			return writeResults(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, rows)
		}
		return nil
	})
	return err
}

func createComparisonRow(pkg string, result *govulncheck.SandboxResponse, baseRow *govulncheck.Result, mode string) (row *govulncheck.Result) {
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
	if mode == modeBinary {
		row.ScanMode = "COMPARE - BINARY"
		row.BinaryBuildSeconds = bigquery.NullFloat(result.Stats.BuildTime.Seconds())
	} else {
		row.ScanMode = "COMPARE - SOURCE"
	}

	vulns := []*govulncheck.Vuln{}
	for _, finding := range result.Findings {
		vulns = append(vulns, govulncheck.ConvertGovulncheckFinding(finding))
	}
	row.Vulns = vulnsForMode(vulns, mode)

	row.ScanMemory = int64(result.Stats.ScanMemory)
	row.ScanSeconds = result.Stats.ScanSeconds

	return row
}

func (s *scanner) ScanModule(ctx context.Context, w http.ResponseWriter, sreq *govulncheck.Request) error {
	if sreq.Module == "std" {
		return nil // ignore the standard library
	}
	row := &govulncheck.Result{
		ModulePath:  sreq.Module,
		Suffix:      sreq.Suffix,
		WorkVersion: *s.workVersion,
		ScanMode:    sreq.Mode,
		ImportedBy:  sreq.ImportedBy,
	}
	row.VulnDBLastModified = s.workVersion.VulnDBLastModified

	// Scan the version.
	log.Debugf(ctx, "fetching proxy info: %s@%s", sreq.Path(), sreq.Version)
	info, err := s.proxyClient.Info(ctx, sreq.Module, sreq.Version)
	if err != nil {
		log.Infof(ctx, "proxy error: %s@%s %v", sreq.Path(), sreq.Version, err)
		row.AddError(fmt.Errorf("%v: %w", err, derrors.ProxyError))
		// TODO: should we also make a copy for imports mode?
		return writeResult(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, row)
	}
	row.Version = info.Version
	row.SortVersion = version.ForSorting(row.Version)
	row.CommitTime = info.Time

	if sreq.Mode == ModeCompare {
		return s.CompareModule(ctx, w, sreq, info, row)
	}

	log.Infof(ctx, "running scanner.runScanModule: %s@%s", sreq.Path(), sreq.Version)
	stats := &govulncheck.ScanStats{}
	vulns, err := s.runScanModule(ctx, sreq.Module, info.Version, sreq.Mode, stats)
	row.ScanSeconds = stats.ScanSeconds
	row.ScanMemory = int64(stats.ScanMemory)
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
		default:
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleGovulncheckError)
		}
		row.AddError(err)
	} else {
		row.Vulns = vulnsForMode(vulns, sreq.Mode)
	}
	log.Infof(ctx, "scanner.runScanModule returned %d vulns for %s: row.Vulns=%d err=%v", len(vulns), sreq.Path(), len(row.Vulns), err)

	rows := []bigquery.Row{row}
	if sreq.Mode == ModeGovulncheck {
		// For ModeGovulncheck, add the copy of row and report
		// each vulnerability as imported. We set the performance
		// numbers to 0 since we don't actually perform a scan
		// at the level of import chains. Also makes a copy if
		// the original row has an error and no vulns.
		impRow := *row
		impRow.ScanMode = modeImports
		impRow.ScanSeconds = 0
		impRow.ScanMemory = 0
		impRow.Vulns = vulnsForMode(vulns, modeImports)
		log.Infof(ctx, "scanner.runScanModule also storing imports vulns for %s: row.Vulns=%d", sreq.Path(), len(impRow.Vulns))
		rows = append(rows, &impRow)
	}
	return writeResults(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, rows)
}

// vulnsForMode returns vulns that make sense to report for
// a particular mode.
//
// For ModeGovulncheck, these are all vulns that are actually
// called. For modeImports, these are all vulns, called or just
// imported. For modeBinary, these are exactly all the vulns
// since binary analysis does not distinguish between called
// and imported vulnerabilities.
func vulnsForMode(vulns []*govulncheck.Vuln, mode string) []*govulncheck.Vuln {
	if mode == modeBinary {
		return vulns
	}

	var vs []*govulncheck.Vuln
	for _, v := range vulns {
		if mode == ModeGovulncheck {
			// Return only the called vulns for ModeGovulncheck.
			if v.Called {
				vs = append(vs, v)
			}
		} else if mode == modeImports {
			// For imports mode, return the vulnerability as it
			// is imported, but not called.
			nv := *v
			nv.Called = false
			vs = append(vs, &nv)
		} else {
			panic(fmt.Sprintf("vulnsForMode unsupported mode %s", mode))
		}
	}
	return vs
}

// runScanModule fetches the module version from the proxy, and analyzes its source
// code for vulnerabilities. The analysis of binaries is done in CompareModules.
func (s *scanner) runScanModule(ctx context.Context, modulePath, version, mode string, stats *govulncheck.ScanStats) (bvulns []*govulncheck.Vuln, err error) {
	err = doScan(ctx, modulePath, version, s.insecure, func() (err error) {
		// Download the module first.
		inputPath := moduleDir(modulePath, version)
		defer derrors.Cleanup(&err, func() error { return os.RemoveAll(inputPath) })
		const init = true
		if err := prepareModule(ctx, modulePath, version, inputPath, s.proxyClient, s.insecure, init); err != nil {
			return err
		}

		var findings []*govulncheckapi.Finding
		if s.insecure {
			findings, err = s.runGovulncheckScanInsecure(inputPath, mode, stats)
		} else {
			findings, err = s.runGovulncheckScanSandbox(ctx, inputPath, mode, stats)
		}
		if err != nil {
			return err
		}
		log.Debugf(ctx, "govulncheck stats: %dkb | %vs", stats.ScanMemory, stats.ScanSeconds)

		for _, v := range findings {
			bvulns = append(bvulns, govulncheck.ConvertGovulncheckFinding(v))
		}
		return nil
	})
	return bvulns, err
}

func (s *scanner) runGovulncheckScanSandbox(ctx context.Context, inputPath, mode string, stats *govulncheck.ScanStats) (_ []*govulncheckapi.Finding, err error) {
	smdir := strings.TrimPrefix(inputPath, sandboxRoot)
	err = s.sbox.Validate()
	log.Debugf(ctx, "sandbox Validate returned %v", err)

	response, err := s.runGovulncheckSandbox(ctx, modeToGovulncheckFlag(mode), smdir)
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
