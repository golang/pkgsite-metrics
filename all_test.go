// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows

package main

import (
	"bufio"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

var goHeader = regexp.MustCompile(`^// Copyright 20\d\d The Go Authors\. All rights reserved\.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file\.`)

func TestHeaders(t *testing.T) {
	sfs := os.DirFS(".")
	fs.WalkDir(sfs, ".", func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := sfs.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if !goHeader.MatchReader(bufio.NewReader(f)) {
			t.Errorf("%v: incorrect go header", path)
		}
		return nil
	})
}
