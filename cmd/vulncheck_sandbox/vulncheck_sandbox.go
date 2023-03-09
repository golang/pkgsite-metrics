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
	"log"
	"os"
	"os/exec"

	"golang.org/x/pkgsite-metrics/internal/load"
	"golang.org/x/pkgsite-metrics/internal/worker"
	"golang.org/x/vuln/vulncheck"
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

	if len(args) != 2 {
		fail(errors.New("need two args: mode, and module dir or binary"))
		return
	}
	mode := args[0]
	if !worker.IsValidVulncheckMode(mode) {
		fail(fmt.Errorf("%q is not a valid mode", mode))
		return
	}

	var b []byte
	var err error
	if mode == worker.ModeImports {
		res, err := runImportsAnalysis(context.Background(), args[1], vulnDBDir)
		if err != nil {
			fail(err)
			return
		}
		b, err = json.MarshalIndent(res, "", "\t")
		if err != nil {
			fail(fmt.Errorf("json.MarshalIndent: %v", err))
			return
		}
	} else {
		b, err = runGovulncheck(context.Background(), args[1], mode, vulnDBDir)
		if err != nil {
			fail(err)
			return
		}
	}

	w.Write(b)
	fmt.Println()
}

func runGovulncheck(ctx context.Context, filePath, mode, vulnDBDir string) ([]byte, error) {
	pattern := "./..."
	dir := ""
	if mode == worker.ModeBinary {
		pattern = filePath
	} else {
		dir = filePath
	}

	govulncheckCmd := exec.Command("/binaries/govulncheck", "-json", pattern)
	govulncheckCmd.Dir = dir
	govulncheckCmd.Env = append(govulncheckCmd.Environ(), "GOVULNDB=file://"+vulnDBDir)

	return govulncheckCmd.Output()
}

func runImportsAnalysis(ctx context.Context, moduleDir, vulnDBDir string) (*vulncheck.Result, error) {
	dbClient, err := NewLocalLMTClient(vulnDBDir)
	if err != nil {
		return nil, fmt.Errorf("NewLocalLMTClient: %v", err)
	}
	vcfg := &vulncheck.Config{
		Client:      dbClient,
		ImportsOnly: true,
	}

	// Load all the packages in moduleDir.
	cfg := load.DefaultConfig()
	cfg.Dir = moduleDir
	cfg.Logf = log.Printf
	pkgs, pkgErrors, err := load.Packages(cfg, "./...")
	if err == nil && len(pkgErrors) > 0 {
		err = fmt.Errorf("%v", pkgErrors)
	}
	if err != nil {
		return nil, fmt.Errorf("loading packages: %v", err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages in %s", moduleDir)
	}

	res, err := vulncheck.Source(ctx, vulncheck.Convert(pkgs), vcfg)
	if err != nil {
		return nil, err
	}
	return res, nil
}
