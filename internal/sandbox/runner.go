// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// This program runs another program provided on standard input,
// prints its standard output, then terminates. It logs to stderr.
//
// It first reads all of standard input, then splits it into words on
// whitespace. It treats the first word as the program path and the rest as
// arguments.
package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("runner: ")
	log.Print("starting")
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("read %q", in)
	args := strings.Fields(string(in))
	if len(args) == 0 {
		log.Fatal("no args")
	}
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.Output()
	if err != nil {
		s := err.Error()
		var eerr *exec.ExitError
		if errors.As(err, &eerr) {
			s += ": " + string(bytes.TrimSpace(eerr.Stderr))
		}
		log.Fatalf("%s failed with %s", args[0], s)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		log.Fatal(err)
	}
	log.Print("succeeded")
}
