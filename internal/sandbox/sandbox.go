// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sandbox runs programs in a secure environment.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"unicode"

	"golang.org/x/pkgsite-metrics/internal/derrors"
)

// A Sandbox is a restricted execution environment.
// A Sandbox instance refers to a directory containing an OCI
// bundle (see https://github.com/opencontainers/runtime-spec/blob/main/bundle.md).
type Sandbox struct {
	bundleDir string
	Runsc     string // path to runsc program
}

// New returns a new Sandbox using the bundle in bundleDir.
// The bundle must be configured to run the 'runner' program,
// built from runner.go in this directory.
// The Sandbox expects the runsc program to be on the path.
// That can be overridden by setting the Runsc field.
func New(bundleDir string) *Sandbox {
	return &Sandbox{
		bundleDir: bundleDir,
		Runsc:     "runsc",
	}
}

// Run runs program with args in a sandbox.
// The program argument is the absolute path to the program from
// within the sandbox.
// It is invoked directly, as with [exec.Command]; no shell
// interpretation is performed.
// Its working directory is the bundle filesystem root.
// The program is passed the given arguments, which must not contain whitespace.
//
// If the program succeeds (exits with code 0), its standard output is returned.
// If it fails, the first return value is empty and the error comes from [exec.Command.Output].
func (s *Sandbox) Run(ctx context.Context, program string, args ...string) (stdout []byte, err error) {
	defer derrors.Wrap(&err, "Run(%s, %q)", program, args)
	for _, a := range args {
		if strings.IndexFunc(a, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("arg %q contains whitespace", a)
		}
	}

	// -ignore-cgroups is needed to avoid this error from runsc:
	// cannot set up cgroup for root: configuring cgroup: write /sys/fs/cgroup/cgroup.subtree_control: device or resource busy
	cmd := exec.CommandContext(ctx, s.Runsc, "-ignore-cgroups", "-network=none", "run", "sandbox")
	cmd.Dir = s.bundleDir
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdin := program + " " + strings.Join(args, " ")
	c := make(chan error, 1)
	go func() {
		_, err := io.WriteString(stdinPipe, stdin)
		stdinPipe.Close()
		c <- err
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if err := <-c; err != nil {
		return nil, fmt.Errorf("writing stdin: %w", err)
	}
	return bytes.TrimSpace(out), nil
}
