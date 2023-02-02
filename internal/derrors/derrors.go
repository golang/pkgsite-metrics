// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derrors defines internal error values to categorize the different
// types error semantics.
package derrors

import (
	"errors"
	"fmt"
	"runtime"

	"cloud.google.com/go/errorreporting"
)

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

	// ScanModuleOSError is used to capture issues with writing the module zip
	// to disk during the scan setup process. This is not an error with vulncheck.
	ScanModuleOSError = errors.New("scan module OS error")
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
