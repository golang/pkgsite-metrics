// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derrors defines internal error values to categorize the different
// types of semantic errors.
package derrors

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"cloud.google.com/go/errorreporting"
)

//lint:file-ignore ST1012 prefixing error values with Err would stutter

var (
	// NotFound indicates that a requested entity was not found (HTTP 404).
	NotFound = errors.New("not found")

	// NotFetched means that the proxy returned "not found" with the
	// Disable-Module-Fetch header set. We don't know if the module really
	// doesn't exist, or the proxy just didn't fetch it.
	NotFetched = errors.New("not fetched by proxy")

	// InvalidArgument indicates that the input into the request is invalid in
	// some way (HTTP 400).
	InvalidArgument = errors.New("invalid argument")

	// BadModule indicates a problem with a module.
	BadModule = errors.New("bad module")

	// ProxyTimedOut indicates that a request timed out when fetching from the Module Mirror.
	ProxyTimedOut = errors.New("proxy timed out")

	// ProxyError is used to capture non-actionable server errors returned from the proxy.
	ProxyError = errors.New("proxy error")

	// BigQueryError is used to capture server errors returned by BigQuery.
	BigQueryError = errors.New("BigQuery error")

	// ScanModulePanicError is used to capture panic issues.
	ScanModulePanicError = errors.New("scan module panic")

	// ScanModuleOSError is used to capture issues with writing the module zip
	// to disk during the scan setup process. This is not an error with govulncheck.
	ScanModuleOSError = errors.New("scan module OS error")

	// LoadPackagesError is used to capture general unclassified issues with
	// load packages during the scan setup process. This is not an error with
	// govulncheck. There are specific load packages errors that are categorized
	// separately, e.g., LoadPackagesNoGoModError.
	LoadPackagesError = errors.New("scan module load packages error")

	// LoadPackagesGoVersionError is used to capture issues with loading
	// packages where the module is not supported by the current Go version.
	// This is not an error with any specific scan technique.
	LoadPackagesGoVersionError = errors.New("scan module load packages error: Go version mismatch")

	// LoadPackagesNoGoModError is used to capture a specific issue with
	// loading packages during the scan setup process where a go.mod file
	// is missing. This is not an error with govulncheck.
	LoadPackagesNoGoModError = errors.New("scan module load packages error: does not have go.mod")

	// LoadPackagesNoGoSumError is used to capture a specific issue with
	// loading packages during the scan setup process where a go.sum file
	// is missing. This is not an error with govulncheck.
	LoadPackagesNoGoSumError = errors.New("scan module load packages error: does not have go.sum")

	// LoadPackagesNoRequiredModuleError is used to capture a specific
	// issue with loading packages during the scan setup process where a package
	// is imported but no required module is provided. This is not an error with
	// govulncheck and is likely happening due to outdated go.sum file.
	LoadPackagesNoRequiredModuleError = errors.New("scan module load packages error: no required module provided")

	// LoadPackagesMissingGoSumEntryError is used to capture a specific
	// issue with loading packages during the scan setup process where a package
	// is imported but some of its go.sum entries are missing. This is not an error
	// with govulncheck and is likely happening due to outdated go.sum file.
	LoadPackagesMissingGoSumEntryError = errors.New("scan module load packages error: missing go.sum entry")

	// LoadVendorError occurs when loading a package fails because of a vendor directory.
	LoadVendorError = errors.New("scan module load packages error: -mod=vendor mode")

	// LoadPackagesSyntheticError is like LoadPackagesError, but when the target
	// packages are from a synthetic module, i.e., non-module we converted into a module.
	LoadPackagesSyntheticError = errors.New("scan synthetic module error")

	// LoadPackagesImportedLocalError occurs when packages use a replace directive
	// with a local directory in their go.mod file. This is not an error with govulncheck.
	LoadPackagesImportedLocalError = errors.New("scan module load packages error: package replaces an import with a local file/directory")

	// ScanModuleGovulncheckDBConnectionError is used to capture a specific
	// govulncheck scan error where a connection to vuln db failed.
	ScanModuleGovulncheckDBConnectionError = errors.New("scan module govulncheck error: communication with vuln db failed")

	// ScanModuleGovulncheckError is used to capture general issues where
	// govulncheck fails due to an uncategorized error.
	ScanModuleGovulncheckError = errors.New("scan module govulncheck error")

	// ScanSyntheticModuleError is used to capture general issues where
	// govulncheck or analysis fails due to an uncategorized error on a
	// synthetic module. The failure can be due to loading of packages or
	// due to an issue in the analysis.
	ScanSyntheticModuleError = errors.New("scan synthetic module error")

	// ScanModuleSandboxError is used to capture general sandbox related issues.
	ScanModuleSandboxError = errors.New("sandbox related issue")

	// ScanModuleMemoryLimitExceeded occurs when scanning uses too much memory.
	ScanModuleMemoryLimitExceeded = errors.New("scan module memory limit exceeded")

	// ScanModuleTooManyOpenFiles occurs when there are too many files open while scanning.
	ScanModuleTooManyOpenFiles = errors.New("scan module too many open files")
)

// Wrap adds context to the error and allows
// unwrapping the result to recover the original error.
//
// Example:
//
//	defer derrors.Wrap(&err, "copy(%s, %s)", dst, src)
//	defer derrors.Wrap(&err, "copy(%s, %s)", src, dst)
//
// See Add for an equivalent function that does not allow
// the result to be unwrapped.
func Wrap(errp *error, format string, args ...interface{}) {
	if *errp != nil {
		*errp = fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), *errp)
	}
}

// WrapStack is like Wrap, but adds a stack trace if there isn't one already.
func WrapStack(errp *error, format string, args ...interface{}) {
	if *errp != nil {
		if se := (*StackError)(nil); !errors.As(*errp, &se) {
			*errp = NewStackError(*errp)
		}
		Wrap(errp, format, args...)
	}
}

// StackError wraps an error and adds a stack trace.
type StackError struct {
	Stack []byte
	err   error
}

// NewStackError returns a StackError, capturing a stack trace.
func NewStackError(err error) *StackError {
	// Limit the stack trace to 16K. Same value used in the errorreporting client,
	// cloud.google.com/go@v0.66.0/errorreporting/errors.go.
	var buf [16 * 1024]byte
	n := runtime.Stack(buf[:], false)
	return &StackError{
		err:   err,
		Stack: buf[:n],
	}
}

func (e *StackError) Error() string {
	return e.err.Error() // ignore the stack
}

func (e *StackError) Unwrap() error {
	return e.err
}

// WrapAndReport calls Wrap followed by Report.
func WrapAndReport(errp *error, format string, args ...interface{}) {
	Wrap(errp, format, args...)
	if *errp != nil {
		Report(*errp)
	}
}

var repClient *errorreporting.Client

// SetReportingClient sets an errorreporting client, for use by Report.
func SetReportingClient(c *errorreporting.Client) {
	repClient = c
}

// Report uses the errorreporting API to report an error.
func Report(err error) {
	if repClient != nil {
		repClient.Report(errorreporting.Entry{Error: err})
	}
}

// CategorizeError returns the category for a given error.
func CategorizeError(err error) string {
	switch {
	case errors.Is(err, ScanModuleGovulncheckError):
		return "VULNCHECK - MISC"
	case errors.Is(err, ScanModuleGovulncheckDBConnectionError):
		return "VULNCHECK - DB CONNECTION"
	case errors.Is(err, LoadPackagesError):
		return "LOAD"
	case errors.Is(err, LoadPackagesSyntheticError):
		return "LOAD - SYNTHETIC MODULE"
	case errors.Is(err, LoadPackagesGoVersionError):
		return "LOAD - WRONG GO VERSION"
	case errors.Is(err, LoadPackagesNoGoModError):
		return "LOAD - NO GO.MOD"
	case errors.Is(err, LoadPackagesNoGoSumError):
		return "LOAD - NO GO.SUM"
	case errors.Is(err, LoadPackagesNoRequiredModuleError):
		return "LOAD - NO REQUIRED MODULE"
	case errors.Is(err, LoadPackagesMissingGoSumEntryError):
		return "LOAD - NO GO.SUM ENTRY"
	case errors.Is(err, LoadPackagesImportedLocalError):
		return "LOAD - GO.MOD REPLACES WITH A LOCAL PATH"
	case errors.Is(err, LoadVendorError):
		return "VENDOR"
	case errors.Is(err, ScanModuleOSError):
		return "OS"
	case errors.Is(err, ScanModulePanicError):
		return "PANIC"
	case errors.Is(err, ScanModuleMemoryLimitExceeded):
		return "MEM LIMIT EXCEEDED"
	case errors.Is(err, ScanModuleTooManyOpenFiles):
		return "TOO MANY OPEN FILES"
	case errors.Is(err, ScanModuleSandboxError):
		return "SANDBOX MISC"
	case errors.Is(err, ProxyError):
		return "PROXY"
	case errors.Is(err, BigQueryError):
		return "BIGQUERY"
	case errors.Is(err, ScanSyntheticModuleError):
		return "SYNTHETIC - MISC"
	}
	return "MISC"
}

func IsGoVersionMismatchError(msg string) bool {
	return strings.Contains(msg, "can't be built on Go")
}

// IncludeStderr includes the stderr with an *exec.ExitError.
// If err is not an *exec.ExitError, it returns err.Error().
func IncludeStderr(err error) string {
	var eerr *exec.ExitError
	if errors.As(err, &eerr) {
		return fmt.Sprintf("%v: %s", eerr, bytes.TrimSpace(eerr.Stderr))
	}
	return err.Error()
}

// Cleanup calls f and combines the error with errp.
// It is meant to be deferred.
func Cleanup(errp *error, f func() error) {
	*errp = errors.Join(*errp, f())
}
