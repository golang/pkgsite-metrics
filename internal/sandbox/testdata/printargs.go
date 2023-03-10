// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// This program prints its arguments and exits.
// If an argument begins with a "$", it prints
// the value of the environment variable instead.
// It is used for testing the sandbox package.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("args:\n")
	for i, arg := range os.Args[1:] {
		val := arg
		if len(arg) > 0 && arg[0] == '$' {
			val = os.Getenv(arg[1:])
		}
		fmt.Printf("%d: %q\n", i, val)
	}
}
