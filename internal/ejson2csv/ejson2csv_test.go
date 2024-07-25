// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ejson2csv_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/pkgsite-metrics/internal/ejson2csv"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func run(pb *bytes.Buffer, errors, others, all, one bool) {
	in, err := os.Open(filepath.Join("testdata", "sample.json"))
	must(err)
	ejson2csv.Process(in, pb, errors, others, all, one)
}

var nl []byte = []byte{'\n'}

func expect(t *testing.T, pb *bytes.Buffer, count int) {
	if got := bytes.Count(pb.Bytes(), nl); got != count {
		t.Errorf("Expected %d newlines, got %d", count, got)
	}
}

func TestEmpty(t *testing.T) {
	var b bytes.Buffer
	run(&b, false, false, false, false)
	expect(t, &b, 5)
}

func TestEmptyOne(t *testing.T) {
	var b bytes.Buffer
	run(&b, false, false, false, true)
	expect(t, &b, 3)
}

func TestError(t *testing.T) {
	var b bytes.Buffer
	run(&b, true, false, false, false)
	expect(t, &b, 37)
}

func TestErrorOne(t *testing.T) {
	var b bytes.Buffer
	run(&b, true, false, false, true)
	expect(t, &b, 4)
}
func TestOther(t *testing.T) {
	var b bytes.Buffer
	run(&b, false, true, false, false)
	expect(t, &b, 18)
}

func TestOtherOne(t *testing.T) {
	var b bytes.Buffer
	run(&b, false, true, false, true)
	expect(t, &b, 18)
}

func TestErrorOther(t *testing.T) {
	var b bytes.Buffer
	run(&b, true, true, false, false)
	expect(t, &b, 54)
}

func TestErrorOtherOne(t *testing.T) {
	var b bytes.Buffer
	run(&b, true, true, false, true)
	expect(t, &b, 21)
}

func TestAll(t *testing.T) {
	var b bytes.Buffer
	run(&b, false, false, true, false)
	expect(t, &b, 58)
}

func TestAllOne(t *testing.T) {
	var b bytes.Buffer
	run(&b, false, false, true, true)
	expect(t, &b, 23)
}
