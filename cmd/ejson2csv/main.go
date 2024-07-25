// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// ejson2csv reads JSON from an ecosystem analysis output and converts it into a CSV format.
// The default is to only print diagnostic messages; optionally it will instead produce lines
// for:
//    errors only                     (-e)
//    others, not errors or messages  (-o)
//    errors and others               (-o -e)
//    all entries                     (-a)
//
// Optionally, instead of printing multiple diagnostics or errors for a build,
// only print the first one (-1) -- this can be combined with any other flag
// combination.

import (
	"flag"
	"fmt"
	"golang.org/x/pkgsite-metrics/internal/ejson2csv"
	"os"
)

func main() {
	var errors, others, all, one bool
	flag.BoolVar(&errors, "e", errors, "print non-empty errors instead of messages")
	flag.BoolVar(&others, "o", others, "print other lines, non-error, non-message")
	flag.BoolVar(&all, "a", all, "print all lines")
	flag.BoolVar(&one, "1", all, "print only the first line for messages or errors")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr,
			`ejson2csv converts the JSON output from an ecosystem analysis into a CSV form.
The default is to only output lines for modules whose analysis produced a diagnostic,
but there are options to print errors (-e), non-error/diagnostic (-o), and all (-a).
Combining -e and -o prints everything except diagnostic messages.
`)
	}
	flag.Parse()

	ejson2csv.Process(os.Stdin, os.Stdout, errors, others, all, one)
}
