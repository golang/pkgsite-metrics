// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buildtest provides support for running "go build"
// and similar build/installation commands in tests.
package buildtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var unsupportedGoosGoarch = map[string]bool{
	"darwin/386": true,
	"darwin/arm": true,
}

// GoBuild runs "go build" on dir using the additional environment variables in
// envVarVals, which should be an alternating list of variables and values.
// It returns the path to the resulting binary.
func GoBuild(t *testing.T, dir, tags string, envVarVals ...string) (binaryPath string) {
	switch runtime.GOOS {
	case "android", "js", "ios":
		t.Skipf("skipping on OS without 'go build' %s", runtime.GOOS)
	}

	if len(envVarVals)%2 != 0 {
		t.Fatal("last args should be alternating variables and values")
	}
	var env []string
	if len(envVarVals) > 0 {
		env = os.Environ()
		for i := 0; i < len(envVarVals); i += 2 {
			env = append(env, fmt.Sprintf("%s=%s", envVarVals[i], envVarVals[i+1]))
		}
	}

	gg := lookupEnv("GOOS", env, runtime.GOOS) + "/" + lookupEnv("GOARCH", env, runtime.GOARCH)
	if unsupportedGoosGoarch[gg] {
		t.Skipf("skipping unsupported GOOS/GOARCH pair %s", gg)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	binaryPath = filepath.Join(tmpDir, filepath.Base(abs))
	var exeSuffix string
	if runtime.GOOS == "windows" {
		exeSuffix = ".exe"
	}
	// Make sure we use the same version of go that is running this test.
	goCommandPath := filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix)
	if _, err := os.Stat(goCommandPath); err != nil {
		t.Fatal(err)
	}
	args := []string{"build", "-o", binaryPath + exeSuffix}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command(goCommandPath, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return binaryPath + exeSuffix
}

// lookEnv looks for name in env, a list of "VAR=VALUE" strings. It returns
// the value if name is found, and defaultValue if it is not.
func lookupEnv(name string, env []string, defaultValue string) string {
	for _, vv := range env {
		i := strings.IndexByte(vv, '=')
		if i < 0 {
			// malformed env entry; just ignore it
			continue
		}
		if name == vv[:i] {
			return vv[i+1:]
		}
	}
	return defaultValue
}

// BuildGovulncheck builds the version of govulncheck specified in
// the go.mod file of this repo into the tmpDir. If the installation
// is successful, returns the full path to the binary. Otherwise,
// returns the error. It uses the Go caches as defined by go env.
func BuildGovulncheck(tmpDir string) (string, error) {
	cmd := exec.Command("go", "build", "-o", tmpDir, "golang.org/x/vuln/cmd/govulncheck")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return filepath.Join(tmpDir, "govulncheck"), nil
}
