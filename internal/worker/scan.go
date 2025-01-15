// Copyright 2023 The Go Authors. All rights reserved.
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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/modules"
	"golang.org/x/pkgsite-metrics/internal/proxy"
)

const (
	// sandboxRoot is the root of the sandbox, relative to the docker container.
	sandboxRoot = "/bundle/rootfs"
	// sandboxGoModCache is where the Go module cache resides in its default
	// location, $HOME/go/pkg/mod.
	sandboxGoModCache = "root/go/pkg/mod"

	// modulesDir is the directory where input modules live. The sandbox mounts
	// this directory to the same path internally, so this path works for both
	// secure and insecure modes.
	modulesDir = "/tmp/modules"
)

var activeScans atomic.Int32

func doScan(ctx context.Context, modulePath, version string, insecure bool, f func() error) (err error) {
	defer derrors.Wrap(&err, "doScan(%q, %q)", modulePath, version)

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
			cleanGoCaches(ctx, insecure)
			logMemory(ctx, "after 'go clean'")
		}
	}()
	return f()
}

func cleanGoCaches(ctx context.Context, insecure bool) {
	var (
		out []byte
		err error
	)

	logDiskUsage := func(msg string) {
		log.Debugf(ctx, "sandbox disk usage %s clean:\n%s",
			msg, diskUsage(filepath.Join(sandboxRoot, "root"), modulesDir))
	}

	if insecure {
		if !config.OnCloudRun() {
			// Avoid cleaning the developer's local caches.
			log.Infof(ctx, "not on Cloud Run, so not cleaning caches")
			return
		}
		out, err = exec.Command("go", "clean", "-cache", "-modcache").CombinedOutput()
	} else {
		logDiskUsage("before")
		// We need to clear Go caches after a scan to avoid memory issues. The caches
		// are created and populated outside of the sandbox. We cannot clear them from
		// within the sandbox since "any modifications to the root filesystem are destroyed
		// with the container" (https://gvisor.dev/docs/user_guide/filesystem/). We hence
		// also clean the caches from the outside.
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

// diskUsage runs the du command to determine how much disk space the given
// directories occupy.
func diskUsage(dirs ...string) string {
	out, err := exec.Command("du", append([]string{"-h", "-s"}, dirs...)...).Output()
	if err != nil {
		return fmt.Sprintf("ERROR: %s", derrors.IncludeStderr(err))
	}
	return strings.TrimSpace(string(out))
}

func writeResult(ctx context.Context, serve bool, w http.ResponseWriter, client *bigquery.Client, table string, row bigquery.Row) (err error) {
	defer derrors.Wrap(&err, "writeResult")

	if serve {
		// Write the result to the client instead of uploading to BigQuery.
		return serveJSON(ctx, row, w)
	}
	// Upload to BigQuery.
	if client == nil {
		log.Infof(ctx, "bigquery disabled, not uploading")
		return nil
	}
	return client.Upload(ctx, table, row)
}

// writeResults is like writeResult but stores multiple rows in a single transaction.
func writeResults(ctx context.Context, serve bool, w http.ResponseWriter, client *bigquery.Client, table string, rows []bigquery.Row) (err error) {
	defer derrors.Wrap(&err, "writeResults")

	if serve {
		// Write the results to the client instead of uploading to BigQuery.
		return serveJSON(ctx, rows, w)
	}
	// Upload to BigQuery.
	if client == nil {
		log.Infof(ctx, "bigquery disabled, not uploading")
		return nil
	}
	return bigquery.UploadMany(ctx, client, table, rows, 0)
}

func serveJSON(ctx context.Context, content interface{}, w http.ResponseWriter) error {
	log.Infof(ctx, "serving result to client")
	data, err := json.MarshalIndent(content, "", "    ")
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}
	_, err = w.Write(data)
	if err != nil {
		log.Errorf(ctx, err, "writing to client")
	}
	return nil // No point serving an error, the write already happened.
}

type openFileFunc func(filename string) (io.ReadCloser, error)

// copyToLocalFile opens destPath for writing locally, making it executable if specified.
// It then uses openFile to open srcPath and copies it to the local file.
func copyToLocalFile(destPath string, executable bool, srcPath string, openFile openFileFunc) (err error) {
	defer derrors.Wrap(&err, "copyToFile(%q, %q)", destPath, srcPath)

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
	rc, err := openFile(srcPath)
	if err != nil {
		return err
	}
	defer rc.Close()
	return copyAndClose(destf, rc)
}

// copyAndClose copies r to wc and closes wc.
func copyAndClose(wc io.WriteCloser, r io.Reader) error {
	_, err := io.Copy(wc, r)
	err2 := wc.Close()
	if err == nil {
		err = err2
	}
	return err
}

func gcsOpenFileFunc(ctx context.Context, bucket *storage.BucketHandle) openFileFunc {
	return func(name string) (io.ReadCloser, error) {
		return bucket.Object(name).NewReader(ctx)
	}
}

type prepareModuleArgs struct {
	modulePath, version string
	dir                 string        // where to download the module
	proxyClient         *proxy.Client // for downloading
	insecure            bool          // run without sandbox
	init                bool          // run `go mod init` and `go mod tidy` on modules with no go.mod file
}

// prepareModule prepares a module for scanning, and takes other actions that increase
// the chance that package loading will succeed.
func prepareModule(ctx context.Context, args prepareModuleArgs) error {
	log.Debugf(ctx, "downloading %s@%s to %s", args.modulePath, args.version, args.dir)
	if err := modules.Download(ctx, args.modulePath, args.version, args.dir, args.proxyClient); err != nil {
		log.Debugf(ctx, "download error: %v (%[1]T)", err)
		return err
	}

	hasGoMod := fileExists(filepath.Join(args.dir, "go.mod"))
	if !args.init || hasGoMod {
		// Download all dependencies, using the given directory for the Go module cache
		// if it is non-empty.
		opts := &goCommandOptions{
			dir:      args.dir,
			insecure: args.insecure,
		}
		return runGoCommand(ctx, args.modulePath, args.version, opts, "mod", "download")
	}
	// Run `go mod init` and `go mod tidy`.
	if err := goModInit(ctx, args.modulePath, args.version, args.dir, args.modulePath, args.insecure); err != nil {
		return err
	}
	return goModTidy(ctx, args.modulePath, args.version, args.dir, args.insecure)
}

// moduleDir returns a the path of a directory where the module can be downloaded.
func moduleDir(modulePath, version string) string {
	return filepath.Join(modulesDir, modulePath+"@"+version)
}

func goModInit(ctx context.Context, modulePath, version, dir, name string, insecure bool) error {
	return runGoCommand(ctx, modulePath, version, &goCommandOptions{dir: dir, insecure: insecure}, "mod", "init", name)
}

// goModTidy runs "go mod tidy" on a module in dir.
func goModTidy(ctx context.Context, modulePath, version, dir string, insecure bool) error {
	opts := &goCommandOptions{
		dir:      dir,
		insecure: insecure,
	}
	return runGoCommand(ctx, modulePath, version, opts, "mod", "tidy")
}

type goCommandOptions struct {
	dir      string
	insecure bool
}

// runGoModCommand runs the command `go args...`.
// modulePath and version are present only for messages.
func runGoCommand(ctx context.Context, modulePath, version string, opts *goCommandOptions, args ...string) (err error) {
	argstring := strings.Join(args, " ")
	defer derrors.Wrap(&err, "runGoCommand(%s@%s, %q, %v)", modulePath, version, argstring, opts)
	if opts == nil {
		opts = &goCommandOptions{}
	}
	log.Infof(ctx, "running `go %s` on %s@%s", argstring, modulePath, version)

	cmd := exec.Command("go", args...)
	cmd.Dir = opts.dir
	cmd.Env = cmd.Environ()
	cmd.Env = append(cmd.Env, "GOPROXY=https://proxy.golang.org/cached-only")
	if !opts.insecure {
		// Use sandbox mod cache.
		cmd.Env = append(cmd.Env, "GOMODCACHE="+filepath.Join(sandboxRoot, sandboxGoModCache))
	}
	if _, err := cmd.Output(); err != nil {
		return fmt.Errorf("%w: 'go %s' for %s@%s returned %s",
			derrors.BadModule, argstring, modulePath, version, derrors.IncludeStderr(err))
	}
	log.Infof(ctx, "'go %s' succeeded", argstring)
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
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

func isProxyCacheMiss(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "server response") && strings.Contains(errStr, "temporarily unavailable")
}

// isBuildIssue recognizes general load issues that might not
// be directly captured by govulncheck or analysis binaries.
// These errors happen sometimes when go mod download fails
// but are effectively a build issue from user perspective.
// They often occur for synthetic projects, but module projects
// might have them as well.
func isBuildIssue(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "does not contain package") ||
		strings.Contains(errStr, "but was required") ||
		strings.Contains(errStr, "relative import paths are not supported in module mode")
}

func isSandboxRelatedIssue(err error) bool {
	return strings.Contains(err.Error(), "exit status 137")
}
