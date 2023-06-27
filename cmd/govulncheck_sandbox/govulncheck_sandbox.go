// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program runs govulncheck on a module or a binary and then
// writes the result as JSON. It is intended to be run in a sandbox.
//
// Unless it panics, this program always terminates with exit code 0.
// If there is an error, it writes a JSON object with field "Error".
// Otherwise, it writes a internal/govulncheck.SandboxResponse as JSON.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/worker"
)

// main function for govulncheck sandbox that accepts four inputs
// in the following order:
//   - path to govulncheck
//   - govulncheck mode
//   - input module or binary to analyze
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

	if len(args) != 4 {
		fail(errors.New("need four args: govulncheck path, mode, input module dir or binary, full path to vuln db"))
		return
	}
	mode := args[1]
	if !worker.IsValidGovulncheckMode(mode) {
		fail(fmt.Errorf("%q is not a valid mode", mode))
		return
	}

	resp, err := runGovulncheck(args[0], mode, args[2], args[3])
	if err != nil {
		fail(err)
		return
	}
	b, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		fail(fmt.Errorf("json.MarshalIndent: %v", err))
		return
	}

	w.Write(b)
	fmt.Println()
}

func runGovulncheck(govulncheckPath, mode, filePath, vulnDBDir string) (*govulncheck.SandboxResponse, error) {
	response := govulncheck.SandboxResponse{
		Stats: govulncheck.ScanStats{},
	}
	var modeFlag, pattern string
	switch mode {
	case govulncheck.ModeBinary:
		modeFlag = govulncheck.FlagBinary
		pattern = filePath
	case govulncheck.ModeGovulncheck:
		modeFlag = govulncheck.FlagSource
		pattern = "./..."
	}

	findings, err := govulncheck.RunGovulncheckCmd(govulncheckPath, modeFlag, pattern, filePath, vulnDBDir, &response.Stats)
	if err != nil {
		return nil, err
	}
	response.Findings = findings
	return &response, nil
}
