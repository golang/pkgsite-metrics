// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sandbox runs programs in a secure environment.
package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"

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

// Cmd's exported fields must be a subset of the exported fields of exec.Cmd.
// runner.go must be able to unmarshal a sandbox.Cmd into an exec.Cmd.

// Cmd describes how to run a binary in a sandbox.
type Cmd struct {
	sb *Sandbox

	// Path is the path of the command to run.
	//
	// This is the only field that must be set to a non-zero
	// value. If Path is relative, it is evaluated relative
	// to Dir.
	Path string

	// Args holds command line arguments, including the command as Args[0].
	// If the Args field is empty or nil, Run uses {Path}.
	//
	// In typical use, both Path and Args are set by calling Command.
	Args []string

	// Env specifies the environment of the process.
	// Each entry is of the form "key=value".
	// If Env is nil, the new process uses whatever environment
	// runsc provides by default.
	Env []string

	// Dir specifies the working directory of the command.
	// If Dir is the empty string, Run runs the command in the
	// root of the sandbox filesystem.
	Dir string
}

// Command creates a *Cmd to run path in the sandbox.
// It behaves like [os/exec.Command].
func (s *Sandbox) Command(path string, arg ...string) *Cmd {
	return &Cmd{
		sb:   s,
		Path: path,
		Args: append([]string{path}, arg...),
	}
}

// Output runs Cmd in the sandbox used to create it, and returns its standard output.
func (c *Cmd) Output() (_ []byte, err error) {
	defer derrors.Wrap(&err, "Cmd.Output %q", c.Args)
	// -ignore-cgroups is needed to avoid this error from runsc:
	// cannot set up cgroup for root: configuring cgroup: write /sys/fs/cgroup/cgroup.subtree_control: device or resource busy
	cmd := exec.Command(c.sb.Runsc, "-ignore-cgroups", "-network=none", "run", "sandbox")
	cmd.Dir = c.sb.bundleDir
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	ch := make(chan error, 1)
	go func() {
		_, err := stdinPipe.Write(stdin)
		stdinPipe.Close()
		ch <- err
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if err := <-ch; err != nil {
		return nil, fmt.Errorf("writing stdin: %w", err)
	}
	return bytes.TrimSpace(out), nil
}
