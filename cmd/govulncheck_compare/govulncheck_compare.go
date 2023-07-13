// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program finds all binaries that can be compiled in a module, then runs
// govulncheck on the module and the subpackages that are used for the binaries,
// as well as the binaries themselves (for comparison). It then writes the results
// as JSON. It is intended to be run in a sandbox.
// Unless it panics, this program always terminates with exit code 0.
// If there is an error, it writes a JSON object with field "Error".
// Otherwise, it writes a internal/govulncheck.CompareResponse as JSON.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/exp/slices"
	"golang.org/x/pkgsite-metrics/internal/buildbinary"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
)

// govulncheck compare accepts three inputs in the following order
//   - path to govulncheck
//   - input module to scan
//   - full path to the vulnerability database
func main() {
	flag.Parse()
	run(os.Stdout, flag.Args())
}

func run(w io.Writer, args []string) {
	fail := func(err error) {
		fmt.Fprintf(w, `{"Error": %q}`, err)
		fmt.Fprintln(w)
	}
	if len(args) != 3 {
		fail(errors.New("need three args: govulncheck path, input module dir, full path to vuln db"))
		return
	}
	govulncheckPath := args[0]
	modulePath := args[1]
	vulndbPath := args[2]

	response := govulncheck.CompareResponse{
		FindingsForMod: make(map[string]*govulncheck.ComparePair),
	}

	binaryPaths, err := buildbinary.FindAndBuildBinaries(modulePath)
	if err != nil {
		fail(err)
		return
	}
	defer removeBinaries(binaryPaths)

	// Sort binaryPath keys so that range is deterministic
	keys := make([]string, 0, len(binaryPaths))
	for k := range binaryPaths {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, binaryPath := range keys {
		importPath := binaryPaths[binaryPath]
		pair := govulncheck.ComparePair{
			BinaryResults: govulncheck.SandboxResponse{Stats: govulncheck.ScanStats{}},
			SourceResults: govulncheck.SandboxResponse{Stats: govulncheck.ScanStats{}},
		}

		pair.SourceResults.Findings, err = govulncheck.RunGovulncheckCmd(govulncheckPath, govulncheck.FlagSource, importPath, modulePath, vulndbPath, &pair.SourceResults.Stats)
		if err != nil {
			fail(err)
			return
		}

		pair.BinaryResults.Findings, err = govulncheck.RunGovulncheckCmd(govulncheckPath, govulncheck.FlagBinary, binaryPath, modulePath, vulndbPath, &pair.BinaryResults.Stats)
		if err != nil {
			fail(err)
			return
		}

		response.FindingsForMod[importPath] = &pair
	}

	b, err := json.MarshalIndent(response, "", "\t")
	if err != nil {
		fail(err)
		return
	}

	w.Write(b)
	fmt.Println()
}

func removeBinaries(binaryPaths map[string]string) {
	for path := range binaryPaths {
		os.Remove(path)
	}
}
