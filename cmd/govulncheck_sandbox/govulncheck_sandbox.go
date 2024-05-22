// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program runs govulncheck on a module in source mode and then
// writes the result as JSON. It is intended to be run in a sandbox.
// For running govulncheck on binaries, see cmd/compare_sandbox.
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

	modeFlag := args[1]
	if modeFlag == govulncheck.FlagBinary {
		fail(errors.New("binaries are only analyzed in compare_sandbox"))
		return
	}

	resp, err := runGovulncheck(args[0], modeFlag, args[2], args[3])
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

func runGovulncheck(govulncheckPath, modeFlag, filePath, vulnDBDir string) (*govulncheck.SandboxResponse, error) {
	stats := govulncheck.ScanStats{}

	response, err := govulncheck.RunGovulncheckCmd(govulncheckPath, modeFlag, "./...", filePath, vulnDBDir, &stats)
	if err != nil {
		return nil, err
	}
	response.Stats = stats
	return response, nil
}
