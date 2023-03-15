// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"encoding/json"
	"os/exec"
)

// GoEnv returns the key-value map of `go env`.
func GoEnv() (map[string]string, error) {
	out, err := exec.Command("go", "env", "-json").Output()
	if err != nil {
		return nil, err
	}
	env := make(map[string]string)
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, err
	}
	return env, nil
}
