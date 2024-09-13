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

	binaries, err := buildbinary.FindAndBuildBinaries(modulePath)
	if err != nil {
		fail(err)
		return
	}
	defer removeBinaries(binaries)

	response := govulncheck.CompareResponse{
		FindingsForMod: make(map[string]*govulncheck.ComparePair),
	}
	for _, binary := range binaries {
		pair, err := runComparison(binary, govulncheckPath, modulePath, vulndbPath)
		if err != nil {
			pair = &govulncheck.ComparePair{Error: err.Error()}
		}
		response.FindingsForMod[binary.ImportPath] = pair
	}

	b, err := json.MarshalIndent(response, "", "\t")
	if err != nil {
		fail(err)
		return
	}

	w.Write(b)
	fmt.Println()
}

// runComparison runs both a source mode and an binary mode comparison,
// and returns a govulncheck.ComparePair on success. Otherwise, returns an error.
func runComparison(binary *buildbinary.BinaryInfo, govulncheckPath, modulePath, vulndbPath string) (*govulncheck.ComparePair, error) {
	if binary.Error != nil { // there was an error in building the binary
		return nil, binary.Error
	}

	srcResp, err := govulncheck.RunGovulncheckCmd(govulncheckPath, govulncheck.FlagSource, binary.ImportPath, modulePath, vulndbPath)
	if err != nil {
		return nil, err
	}
	binResp, err := govulncheck.RunGovulncheckCmd(govulncheckPath, govulncheck.FlagBinary, binary.BinaryPath, modulePath, vulndbPath)
	if err != nil {
		return nil, err
	}

	pair := &govulncheck.ComparePair{
		SourceResults: *srcResp,
		BinaryResults: *binResp,
	}
	pair.BinaryResults.Stats.BuildTime = binary.BuildTime
	return pair, nil
}

func removeBinaries(binaryPaths []*buildbinary.BinaryInfo) {
	for _, bin := range binaryPaths {
		os.Remove(bin.BinaryPath)
	}
}
