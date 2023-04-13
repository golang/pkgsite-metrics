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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/version"
	vulnclient "golang.org/x/vuln/client"
	govulncheckapi "golang.org/x/vuln/exp/govulncheck"
)

const (
	// modeImports is used to report results of vulnerability detection at
	// imports level precision. It cannot be directly triggered by scan
	// endpoints. Instead, ModeGovulncheck mode reports its results to show
	// difference in precision of vulnerability detection.
	modeImports string = "IMPORTS"

	// ModeBinary runs the govulncheck binary in binary mode.
	ModeBinary string = "BINARY"

	// ModeGovulncheck runs the govulncheck binary in default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"

	// sandboxGoCache is the location of the Go cache inside the sandbox. The
	// user is root and their $HOME directory is /root. The Go cache resides
	// in its default location, $HOME/.cache/go-build.
	sandboxGoCache = "root/.cache/go-build"
)

// modes is a set of supported govulncheck modes.
var modes = map[string]bool{
	ModeBinary:      true,
	ModeGovulncheck: true,
}

func IsValidGovulncheckMode(mode string) bool {
	return modes[mode]
}

var scanCounter = event.NewCounter("scans", &event.MetricOptions{Namespace: metricNamespace})

// handleScan runs a govulncheck scan for a single input module. It is triggered
// by path /govulncheck/scan/MODULE_VERSION_SUFFIX?params.
//
// See internal/govulncheck.ParseRequest for allowed path forms and query params.
func (h *GovulncheckServer) handleScan(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "handleScan")

	defer func() {
		scanCounter.Record(r.Context(), 1, event.Bool("success", err == nil))
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
	skip, err := h.canSkip(ctx, sreq, scanner)
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
	if err := h.readGovulncheckWorkStates(ctx); err != nil {
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
	// Otherwise, skip if the error is not recoverable
	// TODO: should we perhaps do this at enqueueall point
	// as well? Would that introduce more savings?
	return unrecoverableError(wve.ErrorCategory), nil
}

// unrecoverableError returns true iff errorCategory encodes that
// the project is not a module or it requires local dependencies.
func unrecoverableError(errorCategory string) bool {
	switch errorCategory {
	case derrors.CategorizeError(derrors.LoadPackagesNoGoModError),
		derrors.CategorizeError(derrors.LoadPackagesNoRequiredModuleError),
		derrors.CategorizeError(derrors.LoadPackagesImportedLocalError):
		return true
	default:
		return false
	}
}

func (h *GovulncheckServer) readGovulncheckWorkStates(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.storedWorkStates != nil {
		return nil
	}
	if h.bqClient == nil {
		return nil
	}
	var err error
	h.storedWorkStates, err = govulncheck.ReadWorkStates(ctx, h.bqClient)
	return err
}

// A scanner holds state for scanning modules.
type scanner struct {
	proxyClient *proxy.Client
	dbClient    vulnclient.Client
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
		dbClient:        h.vulndbClient,
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

func (s *scanner) ScanModule(ctx context.Context, w http.ResponseWriter, sreq *govulncheck.Request) error {
	if sreq.Module == "std" {
		return nil // ignore the standard library
	}
	row := &govulncheck.Result{
		ModulePath:  sreq.Module,
		Suffix:      sreq.Suffix,
		WorkVersion: *s.workVersion,
	}
	// Scan the version.
	log.Debugf(ctx, "fetching proxy info: %s@%s", sreq.Path(), sreq.Version)
	info, err := s.proxyClient.Info(ctx, sreq.Module, sreq.Version)
	if err != nil {
		log.Errorf(ctx, err, "proxy error")
		row.AddError(fmt.Errorf("%v: %w", err, derrors.ProxyError))
		return nil
	}
	row.Version = info.Version
	row.SortVersion = version.ForSorting(row.Version)
	row.CommitTime = info.Time
	row.ImportedBy = sreq.ImportedBy
	row.VulnDBLastModified = s.workVersion.VulnDBLastModified
	row.ScanMode = sreq.Mode

	log.Infof(ctx, "running scanner.runScanModule: %s@%s", sreq.Path(), sreq.Version)
	stats := &scanStats{}
	vulns, err := s.runScanModule(ctx, sreq.Module, info.Version, sreq.Suffix, sreq.Mode, stats)
	row.ScanSeconds = stats.scanSeconds
	row.ScanMemory = int64(stats.scanMemory)
	if err != nil {
		switch {
		case isMissingGoMod(err) || isNoModulesSpecified(err):
			// Covers the missing go.mod file cases when running govulncheck in the sandbox
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoModError)
		case isNoRequiredModule(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoRequiredModuleError)
		case isTooManyFiles(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleTooManyOpenFiles)
		case isMissingGoSumEntry(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesMissingGoSumEntryError)
		case isReplacingWithLocalPath(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesImportedLocalError)
		case isModVendor(err):
			err = fmt.Errorf("%v: %w", err, derrors.VendorError)
		default:
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleGovulncheckError)
		}
		row.AddError(err)
	} else {
		row.Vulns = vulnsForMode(vulns, sreq.Mode)
	}
	log.Infof(ctx, "scanner.runScanModule returned %d vulns for %s: row.Vulns=%d err=%v", len(vulns), sreq.Path(), len(row.Vulns), err)

	if err := writeResult(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, row); err != nil {
		return err
	}

	if sreq.Mode != ModeGovulncheck {
		return nil
	}
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
	return writeResult(ctx, sreq.Serve, w, s.bqClient, govulncheck.TableName, &impRow)
}

// vulnsForMode returns vulns that make sense to report for
// a particular mode.
//
// For ModeGovulncheck, these are all vulns that are actually
// called (CallSink!=0). For modeImports, these are all vulns
// modified to have CallSink=0. For ModeBinary, these are
// exactly the input vulns since binary analysis does not
// distinguish between called and imported vulnerabilities.
func vulnsForMode(vulns []*govulncheck.Vuln, mode string) []*govulncheck.Vuln {
	if mode == ModeBinary {
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

type scanStats struct {
	scanSeconds float64
	scanMemory  uint64
}

// runScanModule fetches the module version from the proxy, and analyzes it for
// vulnerabilities.
func (s *scanner) runScanModule(ctx context.Context, modulePath, version, binaryDir, mode string, stats *scanStats) (bvulns []*govulncheck.Vuln, err error) {
	err = doScan(ctx, modulePath, version, s.insecure, func() (err error) {
		// In ModeBinary, path is a file path to the input binary.
		// Otherwise, it is a path to the input module directory.
		inputPath := binaryDir
		if mode != ModeBinary {
			// In source analysis modes, download the module first.
			inputPath = moduleDir(modulePath, version)
			defer derrors.Cleanup(&err, func() error { return os.RemoveAll(inputPath) })
			if err := prepareModule(ctx, modulePath, version, inputPath, s.proxyClient, s.insecure); err != nil {
				return err
			}
		}

		var vulns []*govulncheckapi.Vuln
		if s.insecure {
			vulns, err = s.runGovulncheckScanInsecure(ctx, modulePath, version, inputPath, mode, stats)
		} else {
			vulns, err = s.runGovulncheckScanSandbox(ctx, modulePath, version, inputPath, mode, stats)
		}
		if err != nil {
			return err
		}
		log.Debugf(ctx, "govulncheck stats: %dkb | %vs", stats.scanMemory, stats.scanSeconds)

		for _, v := range vulns {
			bvulns = append(bvulns, govulncheck.ConvertGovulncheckOutput(v)...)
		}
		return nil
	})
	return bvulns, err
}

func (s *scanner) runGovulncheckScanSandbox(ctx context.Context, modulePath, version, inputPath, mode string, stats *scanStats) (_ []*govulncheckapi.Vuln, err error) {
	if mode == ModeBinary {
		return s.runBinaryScanSandbox(ctx, modulePath, version, inputPath, stats)
	}

	smdir := strings.TrimPrefix(inputPath, sandboxRoot)
	err = s.sbox.Validate()
	log.Debugf(ctx, "sandbox Validate returned %v", err)

	response, err := s.runGovulncheckSandbox(ctx, ModeGovulncheck, smdir)
	if err != nil {
		return nil, err
	}
	stats.scanMemory = response.Stats.ScanMemory
	stats.scanSeconds = response.Stats.ScanSeconds
	return response.Res.Vulns, nil
}

func (s *scanner) runBinaryScanSandbox(ctx context.Context, modulePath, version, binDir string, stats *scanStats) ([]*govulncheckapi.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because vulncheck.Binary
	// ultimately requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", gcsBinaryDir, modulePath, version, binDir)
	destDir := s.binaryDir
	log.Debug(ctx, "copying",
		"from", gcsPathname,
		"to", destDir,
		"module", modulePath, "version", version,
		"dir", binDir)
	destf, err := os.CreateTemp(destDir, "govulncheck-binary-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(destf.Name())
	rc, err := s.gcsBucket.Object(gcsPathname).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if err := copyAndClose(destf, rc); err != nil {
		return nil, err
	}

	response, err := s.runGovulncheckSandbox(ctx, ModeBinary, destf.Name())
	if err != nil {
		return nil, err
	}
	stats.scanMemory = response.Stats.ScanMemory
	stats.scanSeconds = response.Stats.ScanSeconds
	return response.Res.Vulns, nil
}

func (s *scanner) runGovulncheckSandbox(ctx context.Context, mode, arg string) (*govulncheck.SandboxResponse, error) {
	goOut, err := s.sbox.Command("/usr/local/go/bin/go", "version").Output()
	if err != nil {
		log.Debugf(ctx, "running go version error: %v", err)
	} else {
		log.Debugf(ctx, "Sandbox running %s", goOut)
	}
	log.Infof(ctx, "running govulncheck in sandbox: mode %s, arg %q", mode, arg)
	cmd := s.sbox.Command(filepath.Join(s.binaryDir, "govulncheck_sandbox"), s.govulncheckPath, mode, arg, s.vulnDBDir)
	stdout, err := cmd.Output()
	log.Infof(ctx, "govulncheck in sandbox finished with err=%v", err)
	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	return govulncheck.UnmarshalSandboxResponse(stdout)
}

func (s *scanner) runGovulncheckScanInsecure(ctx context.Context, modulePath, version, inputPath, mode string, stats *scanStats) (_ []*govulncheckapi.Vuln, err error) {
	if mode == ModeBinary {
		return s.runBinaryScanInsecure(ctx, modulePath, version, inputPath, os.TempDir(), stats)
	}

	vulns, err := s.runGovulncheckCmd("./...", inputPath, stats)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func (s *scanner) runBinaryScanInsecure(ctx context.Context, modulePath, version, binDir, tempDir string, stats *scanStats) ([]*govulncheckapi.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because govulncheck
	// ultimately requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", gcsBinaryDir, modulePath, version, binDir)
	log.Debug(ctx, "copying to temp dir",
		"from", gcsPathname, "module", modulePath, "version", version, "dir", binDir)
	localPathname := filepath.Join(tempDir, "binary")
	if err := copyToLocalFile(localPathname, false, gcsPathname, gcsOpenFileFunc(ctx, s.gcsBucket)); err != nil {
		return nil, err
	}
	vulns, err := s.runGovulncheckCmd(localPathname, "", stats)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func (s *scanner) runGovulncheckCmd(pattern, tempDir string, stats *scanStats) ([]*govulncheckapi.Vuln, error) {
	start := time.Now()
	govulncheckCmd := exec.Command(s.govulncheckPath, "-json", pattern)
	govulncheckCmd.Env = append(govulncheckCmd.Environ(), "GOVULNDB=file://"+s.vulnDBDir)
	govulncheckCmd.Dir = tempDir
	output, err := govulncheckCmd.CombinedOutput()
	if err != nil {
		if e := (&exec.ExitError{}); !errors.As(err, &e) || e.ProcessState.ExitCode() != 3 {
			return nil, fmt.Errorf("govulncheck error: err=%v out=%s", err, output)
		}
	}
	stats.scanSeconds = time.Since(start).Seconds()
	stats.scanMemory = uint64(govulncheckCmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss)

	res, err := govulncheck.UnmarshalGovulncheckResult(output)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func isNoModulesSpecified(err error) bool {
	return strings.Contains(err.Error(), "no modules specified")
}

func isTooManyFiles(err error) bool {
	return strings.Contains(err.Error(), "too many open files")
}

func isNoRequiredModule(err error) bool {
	return strings.Contains(err.Error(), "no required module")
}

func isMissingGoSumEntry(err error) bool {
	return strings.Contains(err.Error(), "missing go.sum entry")
}

func isMissingGoMod(err error) bool {
	return strings.Contains(err.Error(), "no go.mod file")
}

func isModVendor(err error) bool {
	return strings.Contains(err.Error(), "-mod=vendor")
}

func isReplacingWithLocalPath(err error) bool {
	errStr := err.Error()
	matched, err := regexp.MatchString(`replaced by .{0,2}/`, errStr)
	return err == nil && matched && strings.Contains(errStr, "go.mod: no such file")
}
