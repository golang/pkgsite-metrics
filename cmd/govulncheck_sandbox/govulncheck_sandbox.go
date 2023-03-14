// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program runs vulncheck.Source or vulncheck.Binary on a module, then
// writes the result as JSON. It is intended to be run in a sandbox.
//
// Unless it panics, this program always terminates with exit code 0.
// If there is an error, it writes a JSON object with field "Error".
// Otherwise, it writes a vulncheck.Result as JSON.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	igovulncheck "golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/worker"
)

// vulnDBDir should contain a local copy of the vuln DB, with a LAST_MODIFIED
// file containing a timestamp.
var vulnDBDir = flag.String("vulndb", "/go-vulndb", "directory of local vuln DB")

func main() {
	flag.Parse()
	run(os.Stdout, flag.Args(), *vulnDBDir)
}

func run(w io.Writer, args []string, vulnDBDir string) {

	fail := func(err error) {
		fmt.Fprintf(w, `{"Error": %q}`, err)
		fmt.Fprintln(w)
	}

	if len(args) != 3 {
		fail(errors.New("need three args: govulncheck path, mode, and module dir or binary"))
		return
	}
	mode := args[1]
	if !worker.IsValidVulncheckMode(mode) {
		fail(fmt.Errorf("%q is not a valid mode", mode))
		return
	}

	resp, err := runGovulncheck(context.Background(), args[0], mode, args[2], vulnDBDir)
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

func runGovulncheck(ctx context.Context, govulncheckPath, mode, filePath, vulnDBDir string) (*igovulncheck.GovulncheckResponse, error) {
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
	output, err := govulncheckCmd.Output()
	if err != nil {
		// Temporary check because govulncheck currently exits code 3 if any vulns
		// are found but no other errors occurred.
		if e := (&exec.ExitError{}); !errors.As(err, &e) || e.ProcessState.ExitCode() != 3 {
			return nil, err
		}
	}
	response := igovulncheck.GovulncheckResponse{}
	response.Stats.ScanSeconds = time.Since(start).Seconds()
	result, err := igovulncheck.UnmarshalGovulncheckResult(output)
	if err != nil {
		return nil, err
	}
	response.Res = *result
	response.Stats.ScanMemory = uint64(govulncheckCmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss)
	return &response, nil
}
