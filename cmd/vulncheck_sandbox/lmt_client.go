// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

// A LocalLMTClient behaves exactly like a client that has a local source,
// except that it reads the last modified time from a separate file, LAST_MODIFIED,
// instead of using index.json's modified time.
func NewLocalLMTClient(dir string) (vulnc.Client, error) {
	dbpath, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	c, err := vulnc.NewClient([]string{"file://" + dbpath}, vulnc.Options{})
	if err != nil {
		return nil, err
	}
	return &lmtClient{c: c, dir: dir}, nil
}

type lmtClient struct {
	vulnc.Client
	c   vulnc.Client
	dir string
}

func (c *lmtClient) GetByModule(ctx context.Context, mv string) ([]*osv.Entry, error) {
	return c.c.GetByModule(ctx, mv)
}

func (c *lmtClient) GetByID(ctx context.Context, id string) (*osv.Entry, error) {

	return c.c.GetByID(ctx, id)
}
func (c *lmtClient) GetByAlias(ctx context.Context, alias string) ([]*osv.Entry, error) {
	return c.c.GetByAlias(ctx, alias)
}

func (c *lmtClient) ListIDs(ctx context.Context) ([]string, error) {
	return c.c.ListIDs(ctx)
}
func (c *lmtClient) LastModifiedTime(context.Context) (time.Time, error) {
	return readLastModifiedTime(c.dir)
}

func readLastModifiedTime(dir string) (time.Time, error) {
	data, err := os.ReadFile(filepath.Join(dir, "LAST_MODIFIED"))
	if err != nil {
		return time.Time{}, err
	}
	const timeFormat = "02 Jan 2006 15:04:05 GMT"
	return time.Parse(timeFormat, strings.TrimSpace(string(data)))
}
