// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"archive/zip"
	"sync"
)

type modver struct {
	Path    string
	Version string
}

// cache caches proxy info, mod and zip calls.
type cache struct {
	mu sync.Mutex

	infoCache map[modver]*VersionInfo
	modCache  map[modver][]byte

	// One-element zip cache, to avoid a double download.
	// See TestFetchAndUpdateStateCacheZip in internal/worker/fetch_test.go.
	zipKey    modver
	zipReader *zip.Reader
}

func (c *cache) getInfo(modulePath, version string) *VersionInfo {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.infoCache[modver{Path: modulePath, Version: version}]
}

func (c *cache) putInfo(modulePath, version string, v *VersionInfo) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.infoCache == nil {
		c.infoCache = map[modver]*VersionInfo{}
	}
	c.infoCache[modver{Path: modulePath, Version: version}] = v
}

func (c *cache) getMod(modulePath, version string) []byte {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.modCache[modver{Path: modulePath, Version: version}]
}

func (c *cache) putMod(modulePath, version string, b []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.modCache == nil {
		c.modCache = map[modver][]byte{}
	}
	c.modCache[modver{Path: modulePath, Version: version}] = b
}

func (c *cache) getZip(modulePath, version string) *zip.Reader {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.zipKey == (modver{Path: modulePath, Version: version}) {
		return c.zipReader
	}
	return nil
}

func (c *cache) putZip(modulePath, version string, r *zip.Reader) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.zipKey = modver{Path: modulePath, Version: version}
	c.zipReader = r
}
