// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package load provides functions to load Go packages from source code.
package load

import (
	"errors"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/tools/go/packages"
)

// DefaultConfig returns a packages.Config suitable for LoadPackages.
func DefaultConfig() *packages.Config {
	return &packages.Config{
		Mode: packages.NeedName | packages.NeedImports | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedModule,
		Tests:      false,
		BuildFlags: []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))},
	}
}

// Packages loads Go packages from source.
// In addition to the packages, it returns all errors from loading the packages.
//
// If the third return value is non-nil, that indicates a problem performing the
// load itself, not a problem with the code being loaded. In that case, Packages
// tries to classify the error using derrors package.
func Packages(cfg *packages.Config, patterns ...string) ([]*packages.Package, []error, error) {
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		switch {
		case !fileExists(filepath.Join(cfg.Dir, "go.mod")):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoModError)
		case !fileExists(filepath.Join(cfg.Dir, "go.sum")):
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesNoGoSumError)
		default:
			err = fmt.Errorf("%v: %w", err, derrors.LoadPackagesError)
		}
		return nil, nil, err
	}
	var errors []error
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			errors = append(errors, err)
		}
	})
	// Truncate the list of errors. Sometimes the full list is so large that the BigQuery
	// upload payload exceeds the maximum size. And even when that doesn't happen, more
	// than a few errors is just a waste of space.
	const maxErrors = 20
	if len(errors) > maxErrors {
		errors = append(errors[:maxErrors], fmt.Errorf("... and %d more errors", len(errors)-maxErrors))
	}
	return pkgs, errors, nil
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
