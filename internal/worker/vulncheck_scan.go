// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/exp/event"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	"golang.org/x/pkgsite-metrics/internal/sandbox"
	"golang.org/x/pkgsite-metrics/internal/version"
	ivulncheck "golang.org/x/pkgsite-metrics/internal/vulncheck"
	vulnclient "golang.org/x/vuln/client"
	govulncheckapi "golang.org/x/vuln/exp/govulncheck"
)

const (
	// modeImports is used to report results of
	// vulnerability detection at imports level
	// precision. It cannot be directly triggered
	// by scan endpoints. Instead, ModeGovulncheck
	// mode reports its results to show difference
	// in precision of vulnerability detection.
	modeImports string = "IMPORTS"

	// ModeBinary runs the govulncheck binary in
	// binary mode.
	ModeBinary string = "BINARY"

	// ModeGovulncheck runs the govulncheck binary in
	// default (source) mode.
	ModeGovulncheck = "GOVULNCHECK"
)

// modes is a set of supported vulncheck modes
var modes = map[string]bool{
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
	stats := &scanStats{}
	vulns, err := s.runScanModule(ctx, sreq.Module, info.Version, sreq.Suffix, sreq.Mode, stats)
	row.ScanSeconds = stats.scanSeconds
	row.ScanMemory = int64(stats.scanMemory)
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
		row.Vulns = vulnsForMode(vulns, sreq.Mode)
	}
	log.Infof(ctx, "scanner.runScanModule returned %d vulns for %s: row.Vulns=%d err=%v", len(vulns), sreq.Path(), len(row.Vulns), err)

	if err := writeResult(ctx, sreq.Serve, w, s.bqClient, ivulncheck.TableName, row); err != nil {
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
	return writeResult(ctx, sreq.Serve, w, s.bqClient, ivulncheck.TableName, &impRow)
}

// vulnsForMode returns vulns that make sense to report for
// a particular mode.
//
// For ModeGovulncheck, these are all vulns that are actually
// called (CallSink!=0). For modeImports, these are all vulns
// modified to have CallSink=0. For ModeBinary, these are
// exactly the input vulns since binary analysis does not
// distinguish between called and imported vulnerabilities.
func vulnsForMode(vulns []*ivulncheck.Vuln, mode string) []*ivulncheck.Vuln {
	if mode == ModeBinary {
		return vulns
	}

	var vs []*ivulncheck.Vuln
	for _, v := range vulns {
		if mode == ModeGovulncheck {
			// Return only the called vulns for ModeGovulncheck.
			if v.CallSink.Valid && v.CallSink.Int64 != 0 {
				vs = append(vs, v)
			}
		} else if mode == modeImports {
			// For imports mode, return the vulnerability as it
			// is imported, but not called.
			nv := *v
			nv.CallSink = bigquery.NullInt(0)
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

// Inside the sandbox, the user is root and their $HOME directory is /root.
const (
	// The Go module cache resides in its default location, $HOME/go/pkg/mod.
	sandboxGoModCache = "root/go/pkg/mod"
	// The Go cache resides in its default location, $HOME/.cache/go-build.
	sandboxGoCache = "root/.cache/go-build"
	// Where the govulncheck binary lives.
	govulncheckPath = binaryDir + "/govulncheck"
)

// runScanModule fetches the module version from the proxy, and analyzes it for
// vulnerabilities.
func (s *scanner) runScanModule(ctx context.Context, modulePath, version, binaryDir, mode string, stats *scanStats) (bvulns []*ivulncheck.Vuln, err error) {
	err = doScan(ctx, modulePath, version, s.insecure, func() error {
		var vulns []*govulncheckapi.Vuln
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
		return nil
	})
	return bvulns, err
}

func (s *scanner) runGovulncheckScanSandbox(ctx context.Context, modulePath, version, binDir, mode string, stats *scanStats) (_ []*govulncheckapi.Vuln, err error) {
	if mode == ModeBinary {
		return s.runBinaryScanSandbox(ctx, modulePath, version, binDir, stats)
	}

	mdir := moduleDir(modulePath, version)
	defer cleanup(&err, func() error { return os.RemoveAll(mdir) })
	const insecure = false
	if err := prepareModule(ctx, modulePath, version, mdir, s.proxyClient, insecure); err != nil {
		return nil, err
	}

	log.Infof(ctx, "running govulncheck in sandbox: %s@%s", modulePath, version)
	smdir := strings.TrimPrefix(mdir, sandboxRoot)
	stdout, err := s.sbox.Command(binaryDir+"/vulncheck_sandbox", govulncheckPath, ModeGovulncheck, smdir).Output()
	log.Infof(ctx, "done with govulncheck in sandbox: %s@%s err=%v", modulePath, version, err)

	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	response, err := govulncheck.UnmarshalGovulncheckSandboxResponse(stdout)
	if err != nil {
		return nil, err
	}
	stats.scanMemory = response.Stats.ScanMemory
	stats.scanSeconds = response.Stats.ScanSeconds
	log.Debugf(ctx, "govulncheck stats: %dkb | Seconds: %vs", stats.scanMemory, stats.scanSeconds)
	return response.Res.Vulns, nil
}

func (s *scanner) runBinaryScanSandbox(ctx context.Context, modulePath, version, binDir string, stats *scanStats) ([]*govulncheckapi.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because vulncheck.Binary
	// requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", gcsBinaryDir, modulePath, version, binDir)
	const destDir = binaryDir
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
	stdout, err := s.sbox.Command(binaryDir+"/vulncheck_sandbox", govulncheckPath, ModeBinary, destf.Name()).Output()
	log.Infof(ctx, "done with vulncheck in sandbox on %s: %s@%s/%s err=%v", modulePath, version, binDir, destf.Name(), err)

	if err != nil {
		return nil, errors.New(derrors.IncludeStderr(err))
	}
	res, err := govulncheck.UnmarshalGovulncheckResult(stdout)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
}

func (s *scanner) runGovulncheckScanInsecure(ctx context.Context, modulePath, version, binaryDir, mode string, stats *scanStats) (_ []*govulncheckapi.Vuln, err error) {
	if mode == ModeBinary {
		return s.runBinaryScanInsecure(ctx, modulePath, version, binaryDir, os.TempDir(), stats)
	}

	mdir := moduleDir(modulePath, version)
	defer cleanup(&err, func() error { return os.RemoveAll(mdir) })
	if err := prepareModule(ctx, modulePath, version, mdir, s.proxyClient, true); err != nil {
		return nil, err
	}
	start := time.Now()
	vulns, err := runGovulncheckCmd(ctx, "./...", mdir, stats)
	if err != nil {
		return nil, err
	}
	stats.scanSeconds = time.Since(start).Seconds()
	return vulns, nil
}

func (s *scanner) runBinaryScanInsecure(ctx context.Context, modulePath, version, binDir, tempDir string, stats *scanStats) ([]*govulncheckapi.Vuln, error) {
	if s.gcsBucket == nil {
		return nil, errors.New("binary bucket not configured; set GO_ECOSYSTEM_BINARY_BUCKET")
	}
	// Copy the binary from GCS to the local disk, because vulncheck.Binary
	// requires a ReaderAt and GCS doesn't provide that.
	gcsPathname := fmt.Sprintf("%s/%s@%s/%s", gcsBinaryDir, modulePath, version, binDir)
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

func runGovulncheckCmd(ctx context.Context, pattern, tempDir string, stats *scanStats) ([]*govulncheckapi.Vuln, error) {
	govulncheckName := govulncheckPath
	if !fileExists(govulncheckName) {
		govulncheckName = "govulncheck"
	}
	govulncheckCmd := exec.Command(govulncheckName, "-json", pattern)
	govulncheckCmd.Dir = tempDir
	output, err := govulncheckCmd.Output()
	if e := (&exec.ExitError{}); !errors.As(err, &e) && e.ProcessState.ExitCode() != 3 {
		return nil, err
	}
	res, err := govulncheck.UnmarshalGovulncheckResult(output)
	if err != nil {
		return nil, err
	}
	return res.Vulns, nil
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
