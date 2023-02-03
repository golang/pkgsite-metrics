// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derrors defines internal error values to categorize the different
// types error semantics.
package derrors

import (
	"errors"
	"fmt"
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
	// to disk during the scan setup process. This is not an error with vulncheck.
	ScanModuleOSError = errors.New("scan module OS error")

	// ScanModuleLoadPackagesError is used to capture general unclassified issues
	// with load packages during the scan setup process. This is not an error with
	// vulncheck. There are specific load packages errors that are categorized
	// separately, e.g., ScanModuleLoadPackagesNoGoModError.
	ScanModuleLoadPackagesError = errors.New("scan module load packages error")

	// ScanModuleLoadPackagesGoVersionError is used to capture issues with loading
	// packages where the module is not supported by the current Go version. This
	// is not an error with any specific scan technique.
	ScanModuleLoadPackagesGoVersionError = errors.New("scan module load packages error: Go version mismatch")

	// ScanModuleLoadPackagesNoGoModError is used to capture a specific issue
	// with loading packages during the scan setup process where a go.mod file
	// is missing. This is not an error with vulncheck.
	ScanModuleLoadPackagesNoGoModError = errors.New("scan module load packages error: does not have go.mod")

	// ScanModuleLoadPackagesNoGoSumError is used to capture a specific issue
	// with loading packages during the scan setup process where a go.sum file
	// is missing. This is not an error with vulncheck.
	ScanModuleLoadPackagesNoGoSumError = errors.New("scan module load packages error: does not have go.sum")

	// ScanModuleLoadPackagesNoRequiredModuleError is used to capture a specific
	// issue with loading packages during the scan setup process where a package
	// is imported but no required module is provided. This is not an error with
	// vulncheck and is likely happening due to outdated go.sum file.
	ScanModuleLoadPackagesNoRequiredModuleError = errors.New("scan module load packages error: no required module provided")

	// ScanModuleLoadPackagesMissingGoSumEntryError is used to capture a specific
	// issue with loading packages during the scan setup process where a package
	// is imported but some of its go.sum entries are missing. This is not an error
	// with vulncheck and is likely happening due to outdated go.sum file.
	ScanModuleLoadPackagesMissingGoSumEntryError = errors.New("scan module load packages error: missing go.sum entry")

	// ScanModuleVulncheckDBConnectionError is used to capture a specific
	// vulncheck scan error where a connection to vuln db failed.
	ScanModuleVulncheckDBConnectionError = errors.New("scan module vulncheck error: communication with vuln db failed")

	// ScanModuleVulncheckError is used to capture general issues where
	// vulncheck.Source fails due to an uncategorized error.
	ScanModuleVulncheckError = errors.New("scan module vulncheck error")

	// ScanModuleMemoryLimitExceeded occurs when scanning uses too much memory.
	ScanModuleMemoryLimitExceeded = errors.New("scan module memory limit exceeded")
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
	case errors.Is(err, ScanModuleVulncheckError):
		return "VULNCHECK - MISC"
	case errors.Is(err, ScanModuleVulncheckDBConnectionError):
		return "VULNCHECK - DB CONNECTION"
	case errors.Is(err, ScanModuleLoadPackagesError):
		return "LOAD"
	case errors.Is(err, ScanModuleLoadPackagesGoVersionError):
		return "LOAD - WRONG GO VERSION"
	case errors.Is(err, ScanModuleLoadPackagesNoGoModError):
		return "LOAD - NO GO.MOD"
	case errors.Is(err, ScanModuleLoadPackagesNoGoSumError):
		return "LOAD - NO GO.SUM"
	case errors.Is(err, ScanModuleLoadPackagesNoRequiredModuleError):
		return "LOAD - NO REQUIRED MODULE"
	case errors.Is(err, ScanModuleLoadPackagesMissingGoSumEntryError):
		return "LOAD - NO GO.SUM ENTRY"
	case errors.Is(err, ScanModuleOSError):
		return "OS"
	case errors.Is(err, ScanModulePanicError):
		return "PANIC"
	case errors.Is(err, ScanModuleMemoryLimitExceeded):
		return "MEM LIMIT EXCEEDED"
	case errors.Is(err, ProxyError):
		return "PROXY"
	case errors.Is(err, BigQueryError):
		return "BIGQUERY"
	}
	return ""
}

func IsGoVersionMismatchError(msg string) bool {
	return strings.Contains(msg, "can't be built on Go")
}
