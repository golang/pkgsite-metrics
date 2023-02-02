// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// This program prints its arguments and exits.
// It is used for testing the sandbox package.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("args:\n")
	for i, arg := range os.Args[1:] {
		fmt.Printf("%d: %q\n", i, arg)
	}
}
