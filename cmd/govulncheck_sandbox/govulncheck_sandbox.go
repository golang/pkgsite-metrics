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
	"os/exec"
	"syscall"
	"time"

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
	pattern := "./..."
	dir := ""

	if mode == worker.ModeBinary {
		pattern = filePath
	} else {
		dir = filePath
	}

	govulncheckCmd := exec.Command(govulncheckPath, "-json", pattern)
	govulncheckCmd.Dir = dir
	govulncheckCmd.Env = append(govulncheckCmd.Environ(), "GOVULNDB=file://"+vulnDBDir)
	start := time.Now()
	output, err := govulncheckCmd.CombinedOutput()
	if err != nil {
		// Temporary check because govulncheck currently exits code 3 if any vulns
		// are found but no other errors occurred.
		if e := (&exec.ExitError{}); !errors.As(err, &e) || e.ProcessState.ExitCode() != 3 {
			return nil, fmt.Errorf("govulncheck error: err=%v out=%s", err, output)
		}
	}
	response := govulncheck.SandboxResponse{}
	response.Stats.ScanSeconds = time.Since(start).Seconds()
	result, err := govulncheck.UnmarshalGovulncheckResult(output)
	if err != nil {
		return nil, err
	}
	response.Res = *result
	response.Stats.ScanMemory = uint64(govulncheckCmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss)
	return &response, nil
}
