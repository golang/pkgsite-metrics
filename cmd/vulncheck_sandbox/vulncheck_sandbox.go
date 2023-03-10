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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

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

	b, err := runGovulncheck(context.Background(), args[0], mode, args[2], vulnDBDir)
	if err != nil {
		fail(err)
		return
	}
	w.Write(b)
	fmt.Println()
}

func runGovulncheck(ctx context.Context, govulncheckPath, mode, filePath, vulnDBDir string) ([]byte, error) {
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

	return govulncheckCmd.Output()
}
