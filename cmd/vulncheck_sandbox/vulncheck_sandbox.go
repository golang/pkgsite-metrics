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
	if mode == worker.ModeGovulncheck {
		b, err = runGovulncheck(context.Background(), args[1], vulnDBDir)
		if err != nil {
			fail(err)
			return
		}
	} else {
		res, err := runVulncheck(context.Background(), args[1], mode, vulnDBDir)
		if err != nil {
			fail(err)
			return
		}
		b, err = json.MarshalIndent(res, "", "\t")
		if err != nil {
			fail(fmt.Errorf("json.MarshalIndent: %v", err))
			return
		}
	}

	w.Write(b)
	fmt.Println()
}

func runGovulncheck(ctx context.Context, moduleDir, vulnDBDir string) ([]byte, error) {
	goVulncheckCmd := exec.Command("/binaries/govulncheck", "-json", "./...")
	goVulncheckCmd.Dir = moduleDir
	goVulncheckCmd.Env = append(goVulncheckCmd.Environ(), "GOVULNDB=file://"+vulnDBDir)

	return goVulncheckCmd.Output()
}

func runVulncheck(ctx context.Context, filePath, mode, vulnDBDir string) (*vulncheck.Result, error) {
	dbClient, err := NewLocalLMTClient(vulnDBDir)
	if err != nil {
		return nil, fmt.Errorf("NewLocalLMTClient: %v", err)
	}
	vcfg := &vulncheck.Config{
		Client:      dbClient,
		ImportsOnly: mode == worker.ModeImports,
	}

	if mode == worker.ModeBinary {
		binaryFilePath := filePath
		binaryFile, err := os.Open(binaryFilePath)
		if err != nil {
			return nil, err
		}
		defer binaryFile.Close()
		return vulncheck.Binary(ctx, binaryFile, vcfg)
	}
	moduleDir := filePath
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
	if mode == worker.ModeVTAStacks {
		// Do this for call graph analysis.
		_ = vulncheck.CallStacks(res)
	}
	return res, nil

}
