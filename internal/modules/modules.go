// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package modules assists in working with modules, e.g.,
// downloading a module via a Go proxy client.
package modules

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/proxy"
)

// Download fetches module at version via proxyClient and unzips the module
// into dir.
func Download(ctx context.Context, module, version, dir string, proxyClient *proxy.Client) error {
	zipr, err := proxyClient.Zip(ctx, module, version)
	if err != nil {
		return fmt.Errorf("%v: %w", err, derrors.ProxyError)
	}
	log.Debugf(ctx, "writing module zip: %s@%s", module, version)
	stripPrefix := module + "@" + version + "/"
	if err := writeZip(zipr, dir, stripPrefix); err != nil {
		return fmt.Errorf("%v: %w", err, derrors.ScanModuleOSError)
	}
	return nil
}

func writeZip(r *zip.Reader, destination, stripPrefix string) error {
	for _, f := range r.File {
		name := strings.TrimPrefix(f.Name, stripPrefix)
		fpath := filepath.Join(destination, name)
		if !strings.HasPrefix(fpath, filepath.Clean(destination)+string(os.PathSeparator)) {
			return fmt.Errorf("%s is an illegal filepath", fpath)
		}

		// Do not include vendor directory. They currently contain only modules.txt,
		// not the dependencies. This makes package loading fail. Starting with go1.24,
		// there likely won't be any vendor directories at all.
		if vendored(name) {
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		if _, err := io.Copy(outFile, rc); err != nil {
			return err
		}
		if err := outFile.Close(); err != nil {
			return err
		}
		if err := rc.Close(); err != nil {
			return err
		}
	}
	return nil
}

func vendored(path string) bool {
	return path == "vendor" || strings.HasPrefix(path, "vendor"+string(os.PathSeparator))
}
