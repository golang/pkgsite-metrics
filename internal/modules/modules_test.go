// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modules

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"testing"
)

func TestWriteZip(t *testing.T) {
	// Create an in-memory zipped test module.
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	var files = []struct {
		Name, Body string
	}{
		{filepath.Join("golang.org@v0.0.0", "README"), "This is a readme."},
		{filepath.Join("golang.org@v0.0.0", "main"), "package main"},
	}
	for _, file := range files {
		f, err := w.Create(file.Name)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write([]byte(file.Body))
		if err != nil {
			t.Fatal(err)
		}
	}
	err := w.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a zip.Reader for the module.
	br := bytes.NewReader(buf.Bytes())
	r, err := zip.NewReader(br, int64(len(buf.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	if err := writeZip(r, tempDir, ""); err != nil {
		t.Error(err)
	}
	if err := writeZip(r, tempDir, "golang.org@v0.0.0"); err != nil {
		t.Error(err)
	}
}
