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
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
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
	// ModeVTAStacks computes vulnerability call graph
	// and representative call stacks for each
	// vulnerability. Closely resembles the actual logic
	// of govulncheck.
	//
	// ModeVTAStacks is default vulncheck mode.
	ModeVTAStacks string = "VTASTACKS"

	// ModeImports only computes import-level analysis.
	ModeImports string = "IMPORTS"

	// ModeBinary runs vulncheck.Binary
	ModeBinary string = "BINARY"

	// ModeGovulncheck runs the govulncheck binary
	ModeGovulncheck = "GOVULNCHECK"
)

// modes is a set of supported vulncheck modes
var modes = map[string]bool{
	ModeImports:     true,
	ModeVTAStacks:   true,
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
		sreq.Mode = ModeVTAStacks
	}
	if shouldSkip[sreq.Module] {
		log.Infof(ctx, "skipping %s (module in shouldSkip list)", sreq.Path())
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
		log.Infof(ctx, "skipping %s@%s (work version unchanged)", sreq.Module, sreq.Version)
		return nil
	}

	log.Infof(ctx, "scanning: %s", sreq.Path())
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
	log.Infof(ctx, "fetching proxy info: %s@%s", sreq.Module, sreq.Version)
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

	log.Infof(ctx, "scanning: %s", sreq.Path())
	stats := &vulncheckStats{}
	vulns, err := s.runScanModule(ctx, sreq.Module, info.Version, sreq.Suffix, sreq.Mode, stats)
	row.ScanSeconds = stats.scanSeconds
	row.ScanMemory = int64(stats.scanMemory)
	row.PkgsMemory = int64(stats.pkgsMemory)
	row.Workers = config.GetEnvInt("CLOUD_RUN_CONCURRENCY", "0", -1)
	if err != nil {
		// If an error occurred, wrap it accordingly
		if isVulnDBConnection(err) {
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleVulncheckDBConnectionError)
		} else if !errors.Is(err, derrors.ScanModuleMemoryLimitExceeded) && sreq.Mode != ModeGovulncheck {
			err = fmt.Errorf("%v: %w", err, derrors.ScanModuleVulncheckError)
		}
		row.AddError(err)
		log.Infof(ctx, "scanner.runScanModule return error for %s (%v)", sreq.Path(), err)
	} else {
		row.Vulns = vulns
		log.Infof(ctx, "scanner.runScanModule returned %d vulns: %s", len(vulns), sreq.Path())
	}
	if sreq.Serve {
		// Write the result to the client instead of uploading to BigQuery.
		log.Infof(ctx, "serving result to client")
		data, err := json.MarshalIndent(row, "", "    ")
		if err != nil {
			return fmt.Errorf("marshaling result: %w", err)
		}
		w.Write(data)
	} else if s.bqClient == nil {
		log.Infof(ctx, "bigquery disabled, not uploading")
	} else {
		log.Infof(ctx, "uploading to bigquery: %s", sreq.Path())
		if err := s.bqClient.Upload(ctx, ivulncheck.TableName, row); err != nil {
			// This is often caused by:
			// "Upload: googleapi: got HTTP response code 413 with body"
			// which happens for some modules.
			row.AddError(fmt.Errorf("%v: %w", err, derrors.BigQueryError))
			log.Errorf(ctx, err, "bq.Upload for %s", sreq.Path())
		}
	}
	return nil
}

type vulncheckStats struct {
	scanSeconds float64
	scanMemory  uint64
	pkgsMemory  uint64
}

var activeScans atomic.Int32

// runScanModule fetches the module version from the proxy, and analyzes it for
// vulnerabilities.
func (s *scanner) runScanModule(ctx context.Context, modulePath, version, binaryDir, mode string, stats *vulncheckStats) (bvulns []*ivulncheck.Vuln, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%w: %v\n\n%s", derrors.ScanModulePanicError, e, debug.Stack())
		}
	}()

	logMemory(ctx, fmt.Sprintf("before scanning %s@%s", modulePath, version))
	defer logMemory(ctx, fmt.Sprintf("after scanning %s@%s", modulePath, version))

	activeScans.Add(1)
	defer func() {
		if activeScans.Add(-1) == 0 {
			logMemory(ctx, fmt.Sprintf("before 'go clean' for %s@%s", modulePath, version))
			s.cleanGoCaches(ctx)
			logMemory(ctx, "after 'go clean'")
		}
	}()

	if mode != ModeGovulncheck {
		var vulns []*vulncheck.Vuln
		if s.insecure {
			vulns, err = s.runScanModuleInsecure(ctx, modulePath, version, binaryDir, mode, stats)
		} else {
			vulns, err = s.runScanModuleSandbox(ctx, modulePath, version, binaryDir, mode, stats)
		}

		if err != nil {
			return nil, err
		}
		for _, v := range vulns {
			bvulns = append(bvulns, ivulncheck.ConvertVulncheckOutput(v))
		}
	} else { // Govulncheck mode
		var vulns []*govulncheck.Vuln
		if s.insecure {
			vulns, err = s.runGovulncheckScanInsecure(ctx, modulePath, version, stats)
		} else {
			res, err := s.runGovulncheckScanSandbox(ctx, modulePath, version, stats)
			if err != nil {
				return nil, err
			}
			vulns = res.Vulns
		}
		if err != nil {
			return nil, err
		}
		for _, v := range vulns {
			bvulns = append(bvulns, ivulncheck.ConvertGovulncheckOutput(v)...)
		}
	}
	return bvulns, nil
}

func (s *scanner) runGovulncheckScanSandbox(ctx context.Context, modulePath, version string, stats *vulncheckStats) (*govulncheck.Result, error) {
	sandboxDir := "/modules/" + modulePath + "@" + version
	imageDir := "/bundle/rootfs" + sandboxDir
	defer os.RemoveAll(imageDir)

	log.Infof(ctx, "downloading %s@%s to %s", modulePath, version, imageDir)
	if err := modules.Download(ctx, modulePath, version, imageDir, s.proxyClient, true); err != nil {
		log.Debugf(ctx, "download error: %v (%[1]T)", err)
		return nil, err
	}
	// Download all dependencies outside of the sandbox, but use the Go build
	// cache inside the bundle.
	log.Infof(ctx, "running go mod download")
	cmd := exec.Command("go", "mod", "download")
	cmd.Dir = imageDir
	cmd.Env = append(cmd.Environ(),
		"GOPROXY=https://proxy.golang.org",
		"GOMODCACHE=/bundle/rootfs/"+sandboxGoModCache)
	_, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: 'go mod download' for %s@%s returned %s",
			derrors.BadModule, modulePath, version, derrors.IncludeStderr(err))
	}
	log.Infof(ctx, "go mod download succeeded")
	log.Infof(ctx, "%s@%s: running govulncheck in sandbox", modulePath, version)

	govulncheckcmd := s.sbox.Command("/binaries/vulncheck_sandbox", ModeGovulncheck, sandboxDir)

	stdout, err := govulncheckcmd.Output()
	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	return unmarshalGovulncheckOutput(stdout)
}

func (s *scanner) runScanModuleSandbox(ctx context.Context, modulePath, version, binaryDir, mode string, stats *vulncheckStats) ([]*vulncheck.Vuln, error) {
	var (
		res *vulncheck.Result
		err error
	)
	if mode == ModeBinary {
		res, err = s.runBinaryScanSandbox(ctx, modulePath, version, binaryDir, stats)
	} else {
		res, err = s.runSourceScanSandbox(ctx, modulePath, version, mode, stats)
	}
	log.Debugf(ctx, "runScanModuleSandbox %s@%s bin %s, mode %s: got %+v, %v", modulePath, version, binaryDir, mode, res, err)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func (s *scanner) runSourceScanSandbox(ctx context.Context, modulePath, version, mode string, stats *vulncheckStats) (*vulncheck.Result, error) {
	stdout, err := runSourceScanSandbox(ctx, modulePath, version, mode, s.proxyClient, s.sbox)
	if err != nil {
		return nil, err
	}
	return unmarshalVulncheckOutput(stdout)
}

// Inside the sandbox, the user is root and their $HOME directory is /root.
const (
	// The Go module cache resides in its default location, $HOME/go/pkg/mod.
	sandboxGoModCache = "root/go/pkg/mod"
	// The Go cache resides in its default location, $HOME/.cache/go-build.
	sandboxGoCache = "root/.cache/go-build"
)

func runSourceScanSandbox(ctx context.Context, modulePath, version, mode string, proxyClient *proxy.Client, sbox *sandbox.Sandbox) ([]byte, error) {
	sandboxDir, cleanup, err := downloadModuleSandbox(ctx, modulePath, version, proxyClient)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	log.Infof(ctx, "%s@%s: running vulncheck in sandbox", modulePath, version)
	stdout, err := sbox.Command("/binaries/vulncheck_sandbox", mode, sandboxDir).Output()
	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	return stdout, nil
}

func downloadModuleSandbox(ctx context.Context, modulePath, version string, proxyClient *proxy.Client) (string, func(), error) {
	sandboxDir := "/modules/" + modulePath + "@" + version
	imageDir := "/bundle/rootfs" + sandboxDir

	log.Infof(ctx, "downloading %s@%s to %s", modulePath, version, imageDir)
	if err := modules.Download(ctx, modulePath, version, imageDir, proxyClient, true); err != nil {
		log.Debugf(ctx, "download error: %v (%[1]T)", err)
		return "", nil, err
	}
	// Download all dependencies outside of the sandbox, but use the Go build
	// cache ("/bundle/rootfs/" + sandboxGoCache) inside the bundle.
	log.Infof(ctx, "running go mod download")
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
	log.Infof(ctx, "go mod download succeeded")
	return sandboxDir, func() { os.RemoveAll(imageDir) }, nil
}

func (s *scanner) runBinaryScanSandbox(ctx context.Context, modulePath, version, binDir string, stats *vulncheckStats) (*vulncheck.Result, error) {
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
	if err := copyFromGCSToWriter(ctx, destf, s.gcsBucket, gcsPathname); err != nil {
		return nil, err
	}
	log.Infof(ctx, "%s@%s/%s: running vulncheck in sandbox on %s", modulePath, version, binDir, destf.Name())
	stdout, err := s.sbox.Command("/binaries/vulncheck_sandbox", ModeBinary, destf.Name()).Output()
	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	return unmarshalVulncheckOutput(stdout)
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

func (s *scanner) runGovulncheckScanInsecure(ctx context.Context, modulePath, version string, stats *vulncheckStats) (_ []*govulncheck.Vuln, err error) {
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

	log.Debugf(ctx, "fetching module zip: %s@%s", modulePath, version)
	if err := modules.Download(ctx, modulePath, version, tempDir, s.proxyClient, true); err != nil {
		return nil, err
	}
	start := time.Now()
	vulns, err := runGovulncheckCmd(ctx, modulePath, tempDir, stats)
	if err != nil {
		return nil, err
	}
	stats.scanSeconds = time.Since(start).Seconds()

	return vulns, nil
}

func runGovulncheckCmd(ctx context.Context, modulePath, tempDir string, stats *vulncheckStats) ([]*govulncheck.Vuln, error) {
	govulncheckName := "/bundle/rootfs/binaries/govulncheck"
	if !fileExists(govulncheckName) {
		govulncheckName = "govulncheck"
	}
	govulncheckCmd := exec.Command(govulncheckName, "-json", "./...")
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

func (s *scanner) runScanModuleInsecure(ctx context.Context, modulePath, version, binaryDir, mode string, stats *vulncheckStats) (_ []*vulncheck.Vuln, err error) {
	tempDir, err := os.MkdirTemp("", "runScanModule")
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
	return s.runSourceScanInsecure(ctx, modulePath, version, mode, tempDir, stats)
}

func (s *scanner) runSourceScanInsecure(ctx context.Context, modulePath, version, mode, tempDir string, stats *vulncheckStats) ([]*vulncheck.Vuln, error) {
	log.Debugf(ctx, "fetching module zip: %s@%s", modulePath, version)
	if err := modules.Download(ctx, modulePath, version, tempDir, s.proxyClient, true); err != nil {
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
	vcfg := vulncheckConfig(s.dbClient, mode)
	res, peakMem, err := s.runWithMemoryMonitor(ctx, func() (*vulncheck.Result, error) {
		log.Debugf(ctx, "running vulncheck.Source: %s@%s", modulePath, version)
		res, err := vulncheck.Source(cctx, vulncheck.Convert(pkgs), vcfg)
		log.Debugf(ctx, "completed run for vulncheck.Source: %s@%s, err=%v", modulePath, version, err)

		if err != nil {
			return res, err
		}
		if mode == ModeVTAStacks {
			log.Debugf(ctx, "running vulncheck.CallStacks: %s@%s", modulePath, version)
			vulncheck.CallStacks(res)
			log.Debugf(ctx, "completed run for vulncheck.CallStacks: %s@%s, err=%v", modulePath, version, err)
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

func (s *scanner) runBinaryScanInsecure(ctx context.Context, modulePath, version, binDir, tempDir string, stats *vulncheckStats) ([]*vulncheck.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because vulncheck.Binary
	// requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", binaryDir, modulePath, version, binDir)
	log.Debug(ctx, "copying to temp dir",
		"from", gcsPathname, "module", modulePath, "version", version, "dir", binDir)
	localPathname := filepath.Join(tempDir, "binary")
	if err := copyFromGCS(ctx, s.gcsBucket, gcsPathname, localPathname, false); err != nil {
		return nil, err
	}

	binaryFile, err := os.Open(localPathname)
	if err != nil {
		return nil, err
	}
	defer binaryFile.Close()

	start := time.Now()
	runtime.GC()
	// current memory not related to core (go)vulncheck operations.
	preScanMemory := currHeapUsage()
	log.Debugf(ctx, "running vulncheck.Binary: %s", gcsPathname)
	res, err := vulncheck.Binary(ctx, binaryFile, vulncheckConfig(s.dbClient, ModeBinary))
	log.Debugf(ctx, "completed run for vulncheck.Binary: %s, err=%v", gcsPathname, err)
	stats.scanSeconds = time.Since(start).Seconds()
	// TODO: measure peak usage?
	stats.scanMemory = memSubtract(currHeapUsage(), preScanMemory)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func copyFromGCS(ctx context.Context, bucket *storage.BucketHandle, srcPath, destPath string, executable bool) (err error) {
	defer derrors.Wrap(&err, "copyFromGCS(%q, %q)", srcPath, destPath)
	var mode os.FileMode
	if executable {
		mode = 0755
	} else {
		mode = 0644
	}
	destf, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	err1 := copyFromGCSToWriter(ctx, destf, bucket, srcPath)
	err2 := destf.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func copyFromGCSToWriter(ctx context.Context, w io.Writer, bucket *storage.BucketHandle, srcPath string) error {
	gcsReader, err := bucket.Object(srcPath).NewReader(ctx)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, gcsReader)
	return err
}

func isVulnDBConnection(err error) bool {
	s := err.Error()
	return strings.Contains(s, "https://vuln.go.dev") &&
		strings.Contains(s, "connection")
}

func vulncheckConfig(dbClient vulnclient.Client, mode string) *vulncheck.Config {
	cfg := &vulncheck.Config{Client: dbClient}
	switch mode {
	case ModeImports:
		cfg.ImportsOnly = true
	default:
		cfg.ImportsOnly = false
	}
	return cfg
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

func logMemory(ctx context.Context, prefix string) {
	if !config.OnCloudRun() {
		return
	}

	readIntFile := func(filename string) (int, error) {
		data, err := os.ReadFile(filename)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(string(data)))
	}

	const (
		curFilename = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
		maxFilename = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	)

	cur, err := readIntFile(curFilename)
	if err != nil {
		log.Errorf(ctx, err, "reading %s", curFilename)
	}
	max, err := readIntFile(maxFilename)
	if err != nil {
		log.Errorf(ctx, err, "reading %s", maxFilename)
	}

	const G float64 = 1024 * 1024 * 1024

	log.Infof(ctx, "%s: using %.1fG out of %.1fG", prefix, float64(cur)/G, float64(max)/G)
}

const sandboxGoPath = "/usr/local/go/bin/go"

func (s *scanner) cleanGoCaches(ctx context.Context) {
	var (
		out []byte
		err error
	)

	logDiskUsage := func(msg string) {
		log.Debugf(ctx, "sandbox disk usage %s clean:\n%s",
			msg, diskUsage("/bundle/rootfs/root", "/bundle/rootfs/modules"))
	}

	if s.insecure {
		if !config.OnCloudRun() {
			// Avoid cleaning the developer's local caches.
			log.Infof(ctx, "not on Cloud Run, so not cleaning caches")
			return
		}
		out, err = exec.Command("go", "clean", "-cache", "-modcache").CombinedOutput()
	} else {
		logDiskUsage("before")
		// TODO(zpavlinovic): clean within sandbox. Currently, there is a memory leak.
		//out, err = s.sbox.Command(sandboxGoPath, "clean", "-cache", "-modcache").Output()
		c := exec.Command("go", "clean", "-cache", "-modcache")
		c.Env = append(os.Environ(), "GOCACHE=/bundle/rootfs/"+sandboxGoCache, "GOMODCACHE=/bundle/rootfs/"+sandboxGoModCache)
		out, err = c.CombinedOutput()
		if err == nil {
			logDiskUsage("after")
		}
	}

	output := ""
	if len(out) > 0 {
		output = fmt.Sprintf(" with output %s", out)
	}
	if err != nil {
		log.Errorf(ctx, errors.New(derrors.IncludeStderr(err)), "'go clean' failed%s", output)
	} else {
		log.Infof(ctx, "'go clean' succeeded%s", output)
	}
}

// diskUsage runs the du command to determine how much disk space the given
// directories occupy.
func diskUsage(dirs ...string) string {
	out, err := exec.Command("du", append([]string{"-h", "-s"}, dirs...)...).Output()
	if err != nil {
		return fmt.Sprintf("ERROR: %s", derrors.IncludeStderr(err))
	}
	return strings.TrimSpace(string(out))
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
