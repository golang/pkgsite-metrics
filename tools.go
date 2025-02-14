// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file includes the tools the pkgsite-metrics depend on.
// It is never built as it is hidden behind the tools build tag,
// but the modules containing the imported paths below become a
// requirement of the pkgsite-metrics module. That means go mod
// download will fetch them and all of their dependencies. This
// in turn means we can build these dependencies without further
// interaction with the proxy or making any network requests in
// general. This is useful, for instance, for testing in CI
// integrations where network connection is limited.

//go:build tools

package main

import (
	_ "github.com/client9/misspell/cmd/misspell"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "honnef.co/go/tools/cmd/staticcheck"
	_ "mvdan.cc/unparam"
)
