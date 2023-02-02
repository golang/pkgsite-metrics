// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
)

// IncludeStderr includes the stderr with an *exec.ExitError.
// If err is not an *exec.ExitError, it returns err.Error().
func IncludeStderr(err error) string {
	var eerr *exec.ExitError
	if errors.As(err, &eerr) {
		return fmt.Sprintf("%v: %s", eerr, bytes.TrimSpace(eerr.Stderr))
	}
	return err.Error()
}
