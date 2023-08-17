// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildbinary

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/pkgsite-metrics/internal/derrors"
)

type BinaryInfo struct {
	BinaryPath string
	ImportPath string
	BuildTime  time.Duration
	Error      error
}

// FindAndBuildBinaries finds and builds all possible binaries from a given module.
func FindAndBuildBinaries(modulePath string) (binaries []*BinaryInfo, err error) {
	defer derrors.Wrap(&err, "FindAndBuildBinaries")
	buildTargets, err := findBinaries(modulePath)
	if err != nil {
		return nil, err
	}

	for i, target := range buildTargets {
		path, buildTime, err := runBuild(modulePath, target, i)
		b := &BinaryInfo{
			BinaryPath: path,
			ImportPath: target,
			BuildTime:  buildTime,
		}
		if err != nil {
			b.Error = err
		}
		binaries = append(binaries, b)
	}
	return binaries, nil
}

// runBuild takes a given module and import path and attempts to build a binary
func runBuild(modulePath, importPath string, i int) (binaryPath string, buildTime time.Duration, err error) {
	binName := fmt.Sprintf("bin%d", i)
	cmd := exec.Command("go", "build", "-C", modulePath, "-o", binName, importPath)
	start := time.Now()
	if err = cmd.Run(); err != nil {
		return "", 0, err
	}
	buildTime = time.Since(start)
	binaryPath = filepath.Join(modulePath, binName)
	return binaryPath, buildTime, nil
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
