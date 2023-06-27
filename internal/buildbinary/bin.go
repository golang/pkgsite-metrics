// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildbinary

import (
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/pkgsite-metrics/internal/derrors"
)

// TODO: Consider making struct if we want to pass successful binaries & still
// be aware if building others failed for some reason.

// FindAndBuildBinaries finds and builds all possible binaries from a given module.
func FindAndBuildBinaries(modulePath string) (binaries []string, err error) {
	defer derrors.Wrap(&err, "FindAndBuildBinaries")
	buildTargets, err := findBinaries(modulePath)
	if err != nil {
		return nil, err
	}

	for _, target := range buildTargets {
		path, err := runBuild(modulePath, target)
		if err != nil {
			return nil, err
		}
		binaries = append(binaries, path)
	}
	return binaries, nil
}

// runBuild takes a given module and import path and attempts to build a binary
func runBuild(modulePath, importPath string) (binaryPath string, err error) {
	cmd := exec.Command("go", "build", "-C", modulePath, importPath)
	if err = cmd.Run(); err != nil {
		return "", err
	}
	binaryPath = filepath.Join(modulePath, filepath.Base(importPath))
	return binaryPath, nil
}

// findBinaries finds all packages that compile to binaries in a given directory
// and returns a list of those package's import paths.
func findBinaries(dir string) (buildTargets []string, err error) {
	// Running go list with the given arguments only prints the import paths of
	// packages with package "main", that is packages that could potentially
	// be built into binaries.
	cmd := exec.Command("go", "list", "-f", `{{ if eq .Name "main" }} {{ .ImportPath }} {{end}}`, "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return strings.Fields(string(out)), nil
}
