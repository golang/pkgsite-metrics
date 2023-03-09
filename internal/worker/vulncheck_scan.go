// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/load"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/modules"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/version"
	ivulncheck "golang.org/x/pkgsite-metrics/internal/vulncheck"
	vulnclient "golang.org/x/vuln/client"
	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/vulncheck"
)

const (
	// ModeImports performs import-level analysis.
	ModeImports string = "IMPORTS"

	// ModeBinary runs the govulncheck binary in
	// binary mode.
	ModeBinary string = "BINARY"

	// ModeGovulncheck runs the govulncheck binary in
	// default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"
)

// modes is a set of supported vulncheck modes
var modes = map[string]bool{
	ModeImports:     true,
	ModeBinary:      true,
	ModeGovulncheck: true,
}

func IsValidVulncheckMode(mode string) bool {
	return modes[mode]
}

// TODO(b/241402488): shouldSkip is the list of modules that we are not
// currently scanning due to previous issues that need investigation.
var shouldSkip = map[string]bool{}

var scanCounter = event.NewCounter("scans", &event.MetricOptions{Namespace: metricNamespace})

// path: /vulncheck/scan/MODULE_VERSION_SUFFIX?params
// See internal/vulncheck.ParseRequest for allowed path forms and query params.
func (h *VulncheckServer) handleScan(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "handleScan")

	defer func() {
		scanCounter.Record(r.Context(), 1, event.Bool("success", err == nil))
	}()

	ctx := r.Context()
	sreq, err := ivulncheck.ParseRequest(r, "/vulncheck/scan")
	if err != nil {
		return fmt.Errorf("%w: %v", derrors.InvalidArgument, err)
	}
	if sreq.Mode == "" {
		sreq.Mode = ModeGovulncheck
	}
	if shouldSkip[sreq.Module] {
		log.Infof(ctx, "skipping (module in shouldSkip list): %s", sreq.Path())
		return nil
	}
	if err := h.readVulncheckWorkVersions(ctx); err != nil {
		return err
	}
	scanner, err := newScanner(ctx, h)
	if err != nil {
		return err
	}
	// An explicit "insecure" query param overrides the default.
	if sreq.Insecure {
		scanner.insecure = sreq.Insecure
	}
	wv := h.storedWorkVersions[[2]string{sreq.Module, sreq.Version}]
	if scanner.workVersion.Equal(wv) {
		log.Infof(ctx, "skipping (work version unchanged): %s@%s", sreq.Module, sreq.Version)
		return nil
	}

	return scanner.ScanModule(ctx, w, sreq)
}

func (h *VulncheckServer) readVulncheckWorkVersions(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.storedWorkVersions != nil {
		return nil
	}
	if h.bqClient == nil {
		return nil
	}
	var err error
	h.storedWorkVersions, err = ivulncheck.ReadWorkVersions(ctx, h.bqClient)
	return err
}

// A scanner holds state for scanning modules.
type scanner struct {
	proxyClient *proxy.Client
	dbClient    vulnclient.Client
	bqClient    *bigquery.Client
	workVersion *ivulncheck.WorkVersion
	goMemLimit  uint64
	gcsBucket   *storage.BucketHandle
	insecure    bool
	sbox        *sandbox.Sandbox
}

func newScanner(ctx context.Context, h *VulncheckServer) (*scanner, error) {
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
		proxyClient: h.proxyClient,
		bqClient:    h.bqClient,
		dbClient:    h.vulndbClient,
		workVersion: workVersion,
		goMemLimit:  parseGoMemLimit(os.Getenv("GOMEMLIMIT")),
		gcsBucket:   bucket,
		insecure:    h.cfg.Insecure,
		sbox:        sbox,
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

func (s *scanner) ScanModule(ctx context.Context, w http.ResponseWriter, sreq *ivulncheck.Request) error {
	if sreq.Module == "std" {
		return nil // ignore the standard library
	}
	row := &ivulncheck.Result{
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
	stats := &vulncheckStats{}
	vulns, err := s.runScanModule(ctx, sreq.Module, info.Version, sreq.Suffix, sreq.Mode, stats)
	row.ScanSeconds = stats.scanSeconds
	row.ScanMemory = int64(stats.scanMemory)
	row.PkgsMemory = int64(stats.pkgsMemory)
	row.Workers = config.GetEnvInt("CLOUD_RUN_CONCURRENCY", "0", -1)
	if err != nil {
		switch {
		case errors.Is(err, derrors.LoadPackagesNoGoModError) ||
			errors.Is(err, derrors.LoadPackagesNoGoSumError):
			// errors already classified by package loading.
		case isMissingGoMod(err):
			// specific for govulncheck
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoModError)
		case isNoRequiredModule(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoRequiredModuleError)
		case isMissingGoSumEntry(err):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesMissingGoSumEntryError)
		case errors.Is(err, derrors.LoadPackagesError):
			// general load packages error
		case isVulnDBConnection(err):
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleVulncheckDBConnectionError)
		default:
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleVulncheckError)
		}
		row.AddError(err)
	} else {
		row.Vulns = vulns
	}
	log.Infof(ctx, "done with scanner.runScanModule: %s@%s #vulns=%d err=%v", sreq.Path(), sreq.Version, len(vulns), err)
	return writeResult(ctx, sreq.Serve, w, s.bqClient, ivulncheck.TableName, row)
}

type vulncheckStats struct {
	scanSeconds float64
	scanMemory  uint64
	pkgsMemory  uint64
}

// Inside the sandbox, the user is root and their $HOME directory is /root.
const (
	// The Go module cache resides in its default location, $HOME/go/pkg/mod.
	sandboxGoModCache = "root/go/pkg/mod"
	// The Go cache resides in its default location, $HOME/.cache/go-build.
	sandboxGoCache = "root/.cache/go-build"
)

// runScanModule fetches the module version from the proxy, and analyzes it for
// vulnerabilities.
func (s *scanner) runScanModule(ctx context.Context, modulePath, version, binaryDir, mode string, stats *vulncheckStats) (bvulns []*ivulncheck.Vuln, err error) {
	err = doScan(ctx, modulePath, version, s.insecure, func() error {
		if mode == ModeImports {
			var vulns []*vulncheck.Vuln
			if s.insecure {
				vulns, err = s.runImportsScanInsecure(ctx, modulePath, version, stats)
			} else {
				vulns, err = s.runImportsScanSandbox(ctx, modulePath, version, stats)
			}
			if err != nil {
				return err
			}
			for _, v := range vulns {
				bvulns = append(bvulns, ivulncheck.ConvertVulncheckOutput(v))
			}
		} else {
			var vulns []*govulncheck.Vuln
			if s.insecure {
				vulns, err = s.runGovulncheckScanInsecure(ctx, modulePath, version, binaryDir, mode, stats)
			} else {
				vulns, err = s.runGovulncheckScanSandbox(ctx, modulePath, version, binaryDir, mode, stats)
			}
			if err != nil {
				return err
			}
			for _, v := range vulns {
				bvulns = append(bvulns, ivulncheck.ConvertGovulncheckOutput(v)...)
			}
		}
		return nil
	})
	return bvulns, err
}

func (s *scanner) runImportsScanInsecure(ctx context.Context, modulePath, version string, stats *vulncheckStats) (_ []*vulncheck.Vuln, err error) {
	tempDir, err := os.MkdirTemp("", "runImportsScan")
	if err != nil {
		return nil, err
	}

	defer func() {
		err1 := os.RemoveAll(tempDir)
		if err == nil {
			err = err1
		}
	}()

	log.Debugf(ctx, "fetching module zip: %s@%s", modulePath, version)
	if err = modules.Download(ctx, modulePath, version, tempDir, s.proxyClient, true); err != nil {
		return nil, err
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg := load.DefaultConfig()
	cfg.Dir = tempDir // filepath.Join(dir, modulePath+"@"+version,
	cfg.Context = cctx

	runtime.GC()
	// current memory not related to core (go)vulncheck operations.
	preScanMemory := currHeapUsage()

	log.Debugf(ctx, "loading packages: %s@%s", modulePath, version)
	pkgs, pkgErrors, err := load.Packages(cfg, "./...")
	if err == nil && len(pkgErrors) > 0 {
		err = fmt.Errorf("%v", pkgErrors)
	}
	if err != nil {
		return nil, err
	}

	stats.pkgsMemory = memSubtract(currHeapUsage(), preScanMemory)

	// Run vulncheck.Source and collect results.
	start := time.Now()
	vcfg := &vulncheck.Config{Client: s.dbClient, ImportsOnly: true}
	res, peakMem, err := s.runWithMemoryMonitor(ctx, func() (*vulncheck.Result, error) {
		log.Infof(ctx, "running imports analysis (vulncheck.Source): %s@%s", modulePath, version)
		res, err := vulncheck.Source(cctx, vulncheck.Convert(pkgs), vcfg)
		log.Infof(ctx, "done with imports analysis (vulncheck.Source): %s@%s, err=%v", modulePath, version, err)
		if err != nil {
			return res, err
		}
		return res, nil
	})
	// scanMemory is peak heap memory used during vulncheck + pkgs.
	// We subtract any memory not related to these core (go)vulncheck
	// operations.
	stats.scanMemory = memSubtract(peakMem, preScanMemory)

	// scanSeconds is the time it took for vulncheck.Source to run.
	// We want to know this information regardless of whether an error
	// occurred.
	stats.scanSeconds = time.Since(start).Seconds()
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func (s *scanner) runImportsScanSandbox(ctx context.Context, modulePath, version string, stats *vulncheckStats) ([]*vulncheck.Vuln, error) {
	sandboxDir, cleanup, err := downloadModuleSandbox(ctx, modulePath, version, s.proxyClient)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	log.Infof(ctx, "running imports analysis in sandbox: %s@%s", modulePath, version)
	stdout, err := s.sbox.Command("/binaries/vulncheck_sandbox", ModeImports, sandboxDir).Output()
	log.Infof(ctx, "done with imports analysis in sandbox: %s@%s err=%v", modulePath, version, err)

	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	res, err := unmarshalVulncheckOutput(stdout)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func (s *scanner) runGovulncheckScanSandbox(ctx context.Context, modulePath, version, binaryDir, mode string, stats *vulncheckStats) ([]*govulncheck.Vuln, error) {
	if mode == ModeBinary {
		return s.runBinaryScanSandbox(ctx, modulePath, version, binaryDir, stats)
	}

	sandboxDir, cleanup, err := downloadModuleSandbox(ctx, modulePath, version, s.proxyClient)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	log.Infof(ctx, "running govulncheck in sandbox: %s@%s", modulePath, version)
	stdout, err := s.sbox.Command("/binaries/vulncheck_sandbox", ModeGovulncheck, sandboxDir).Output()
	log.Infof(ctx, "done with govulncheck in sandbox: %s@%s err=%v", modulePath, version, err)

	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	res, err := unmarshalGovulncheckOutput(stdout)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func downloadModuleSandbox(ctx context.Context, modulePath, version string, proxyClient *proxy.Client) (string, func(), error) {
	sandboxDir := "/modules/" + modulePath + "@" + version
	imageDir := "/bundle/rootfs" + sandboxDir

	log.Debugf(ctx, "downloading %s@%s to %s", modulePath, version, imageDir)
	if err := modules.Download(ctx, modulePath, version, imageDir, proxyClient, true); err != nil {
		log.Debugf(ctx, "download error: %v (%[1]T)", err)
		return "", nil, err
	}
	// Download all dependencies outside of the sandbox, but use the Go build
	// cache ("/bundle/rootfs/" + sandboxGoCache) inside the bundle.
	log.Debugf(ctx, "running go mod download")
	cmd := exec.Command("go", "mod", "download")
	cmd.Dir = imageDir
	cmd.Env = append(cmd.Environ(),
		"GOPROXY=https://proxy.golang.org",
		"GOMODCACHE=/bundle/rootfs/"+sandboxGoModCache)
	_, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("%w: 'go mod download' for %s@%s returned %s",
			derrors.BadModule, modulePath, version, derrors.IncludeStderr(err))
	}
	log.Debugf(ctx, "go mod download succeeded")
	return sandboxDir, func() { os.RemoveAll(imageDir) }, nil
}

func (s *scanner) runBinaryScanSandbox(ctx context.Context, modulePath, version, binDir string, stats *vulncheckStats) ([]*govulncheck.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because vulncheck.Binary
	// requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", binaryDir, modulePath, version, binDir)
	const destDir = "/bundle/rootfs/binaries"
	log.Debug(ctx, "copying",
		"from", gcsPathname,
		"to", destDir,
		"module", modulePath, "version", version,
		"dir", binDir)
	destf, err := os.CreateTemp(destDir, "vulncheck-binary-")
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

	log.Infof(ctx, "running vulncheck in sandbox on %s: %s@%s/%s", modulePath, version, binDir, destf.Name())
	stdout, err := s.sbox.Command("/binaries/vulncheck_sandbox", ModeBinary, destf.Name()).Output()
	log.Infof(ctx, "done with vulncheck in sandbox on %s: %s@%s/%s err=%v", modulePath, version, binDir, destf.Name(), err)

	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	res, err := unmarshalGovulncheckOutput(stdout)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func (s *scanner) runGovulncheckScanInsecure(ctx context.Context, modulePath, version, binaryDir, mode string, stats *vulncheckStats) (_ []*govulncheck.Vuln, err error) {
	tempDir, err := os.MkdirTemp("", "runGovulncheckScan")
	if err != nil {
		return nil, err
	}

	defer func() {
		err1 := os.RemoveAll(tempDir)
		if err == nil {
			err = err1
		}
	}()

	if mode == ModeBinary {
		return s.runBinaryScanInsecure(ctx, modulePath, version, binaryDir, tempDir, stats)
	}

	log.Debugf(ctx, "fetching module zip: %s@%s", modulePath, version)
	if err := modules.Download(ctx, modulePath, version, tempDir, s.proxyClient, true); err != nil {
		return nil, err
	}
	start := time.Now()
	vulns, err := runGovulncheckCmd(ctx, "./...", tempDir, stats)
	if err != nil {
		return nil, err
	}
	stats.scanSeconds = time.Since(start).Seconds()
	return vulns, nil
}

func (s *scanner) runBinaryScanInsecure(ctx context.Context, modulePath, version, binDir, tempDir string, stats *vulncheckStats) ([]*govulncheck.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because vulncheck.Binary
	// requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", binaryDir, modulePath, version, binDir)
	log.Debug(ctx, "copying to temp dir",
		"from", gcsPathname, "module", modulePath, "version", version, "dir", binDir)
	localPathname := filepath.Join(tempDir, "binary")
	if err := copyToLocalFile(localPathname, false, gcsPathname, gcsOpenFileFunc(ctx, s.gcsBucket)); err != nil {
		return nil, err
	}

	start := time.Now()
	vulns, err := runGovulncheckCmd(ctx, localPathname, "", stats)
	if err != nil {
		return nil, err
	}
	stats.scanSeconds = time.Since(start).Seconds()
	return vulns, nil
}

func runGovulncheckCmd(ctx context.Context, pattern, tempDir string, stats *vulncheckStats) ([]*govulncheck.Vuln, error) {
	govulncheckName := "/bundle/rootfs/binaries/govulncheck"
	if !fileExists(govulncheckName) {
		govulncheckName = "govulncheck"
	}
	govulncheckCmd := exec.Command(govulncheckName, "-json", pattern)
	govulncheckCmd.Dir = tempDir
	output, err := govulncheckCmd.Output()
	if err != nil {
		return nil, err
	}
	res, err := unmarshalGovulncheckOutput(output)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func unmarshalVulncheckOutput(output []byte) (*vulncheck.Result, error) {
	var e struct {
		Error string
	}
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res vulncheck.Result
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func unmarshalGovulncheckOutput(output []byte) (*govulncheck.Result, error) {
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

// runWithMemoryMonitor runs f in a goroutine with its memory tracked.
// It returns f's peak memory usage.
func (s *scanner) runWithMemoryMonitor(ctx context.Context, f func() (*vulncheck.Result, error)) (res *vulncheck.Result, mem uint64, err error) {
	cctx, cancel := context.WithCancel(ctx)
	monitor := newMemMonitor(s.goMemLimit, cancel)
	type sr struct {
		res *vulncheck.Result
		err error
	}
	srchan := make(chan sr)
	go func() {
		res, err := f()
		srchan <- sr{res, err}
	}()
	select {
	case r := <-srchan:
		res = r.res
		err = r.err
	case <-cctx.Done():
		err = derrors.ScanModuleMemoryLimitExceeded
	}
	return res, monitor.stop(), err
}

func copyFromGCSToWriter(ctx context.Context, w io.Writer, bucket *storage.BucketHandle, srcPath string) error {
	gcsReader, err := bucket.Object(srcPath).NewReader(ctx)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, gcsReader)
	return err
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

func isVulnDBConnection(err error) bool {
	s := err.Error()
	return strings.Contains(s, "https://vuln.go.dev") &&
		strings.Contains(s, "connection")
}

// currHeapUsage computes currently allocate heap bytes.
func currHeapUsage() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.Alloc
}

// memSubtract subtracts memory usage m2 from m1, returning
// 0 if the result is negative.
func memSubtract(m1, m2 uint64) uint64 {
	if m1 <= m2 {
		return 0
	}
	return m1 - m2
}

// parseGoMemLimit parses the GOMEMLIMIT environment variable.
// It returns 0 if the variable isn't set or its value is malformed.
func parseGoMemLimit(s string) uint64 {
	if len(s) < 2 {
		return 0
	}
	m := uint64(1)
	if s[len(s)-1] == 'i' {
		switch s[len(s)-2] {
		case 'K':
			m = 1024
		case 'M':
			m = 1024 * 1024
		case 'G':
			m = 1024 * 1024 * 1024
		default:
			return 0
		}
		s = s[:len(s)-2]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v * m
}

// fileExists checks if file path exists. Returns true
// if the file exists or it cannot prove that it does
// not exist. Otherwise, returns false.
func fileExists(file string) bool {
	if _, err := os.Stat(file); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	}
	// Conservatively return true if os.Stat fails
	// for some other reason.
	return true
}
