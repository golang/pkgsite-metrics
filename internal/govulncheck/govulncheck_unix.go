// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package govulncheck

import (
	"os/exec"
	"syscall"
)

func init() {
	getMemoryUsage = func(c *exec.Cmd) uint64 {
		return uint64(c.ProcessState.SysUsage().(*syscall.Rusage).Maxrss)
	}
}
