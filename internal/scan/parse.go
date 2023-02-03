// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/version"
)

// Request contains information passed
// to a scan endpoint.
type Request struct {
	Module     string
	Version    string
	Suffix     string
	ImportedBy int
	Mode       string
	Insecure   bool

	// TODO: support optional parameters?
}

func (r *Request) URLPathAndParams() string {
	suf := r.Suffix
	if suf != "" {
		suf = "/" + suf
	}
	return fmt.Sprintf("%s/@v/%s%s?importedby=%d&mode=%s&insecure=%t", r.Module, r.Version, suf, r.ImportedBy, r.Mode, r.Insecure)
}

func (r *Request) Path() string {
	p := r.Module + "@" + r.Version
	if r.Suffix != "" {
		p += "/" + r.Suffix
	}
	return p
}

// ParseRequest parses an http request r for an endpoint
// scanPrefix and produces a corresponding ScanRequest.
//
// The module and version should have one of the following three forms:
//   - <module>/@v/<version>
//   - <module>@<version>
//   - <module>/@latest
//
// (These are the same forms that the module proxy accepts.)
func ParseRequest(r *http.Request, scanPrefix string) (*Request, error) {
	mod, vers, suff, err := ParseModuleVersionSuffix(strings.TrimPrefix(r.URL.Path, scanPrefix))
	if err != nil {
		return nil, err
	}
	importedBy, err := ParseRequiredIntParam(r, "importedby")
	if err != nil {
		return nil, err
	}
	insecure, err := ParseOptionalBoolParam(r, "insecure", false)
	if err != nil {
		return nil, err
	}
	return &Request{
		Module:     mod,
		Version:    vers,
		Suffix:     suff,
		ImportedBy: importedBy,
		Mode:       ParseMode(r),
		Insecure:   insecure,
	}, nil
}

// ParseModuleVersionSuffix returns the module path, version and suffix described by
// the argument. The suffix is the part of the path after the version.
func ParseModuleVersionSuffix(requestPath string) (path, vers, suffix string, err error) {
	p := strings.TrimPrefix(requestPath, "/")
	modulePath, versionAndSuffix, found := strings.Cut(p, "@")
	if !found {
		return "", "", "", fmt.Errorf("invalid path %q: missing '@'", requestPath)
	}
	modulePath = strings.TrimSuffix(modulePath, "/")
	if modulePath == "" {
		return "", "", "", fmt.Errorf("invalid path %q: missing module", requestPath)
	}
	if strings.HasPrefix(versionAndSuffix, "v/") {
		versionAndSuffix = versionAndSuffix[2:]
	}
	// Now versionAndSuffix begins with a version.
	version, suffix, _ := strings.Cut(versionAndSuffix, "/")
	if version == "" {
		return "", "", "", fmt.Errorf("invalid path %q: missing version", requestPath)
	}
	if version[0] != 'v' {
		version = "v" + version
	}
	return modulePath, version, suffix, nil
}

func ParseRequiredIntParam(r *http.Request, name string) (int, error) {
	value := r.FormValue(name)
	if value == "" {
		return 0, fmt.Errorf("missing query param %q", name)
	}
	return ParseIntParam(value, name)
}

func ParseOptionalIntParam(r *http.Request, name string, def int) (int, error) {
	value := r.FormValue(name)
	if value == "" {
		return def, nil
	}
	return ParseIntParam(value, name)
}

func ParseIntParam(value, name string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("want integer for %q query param, got %q", name, value)
	}
	return n, nil
}

func ParseOptionalBoolParam(r *http.Request, name string, def bool) (bool, error) {
	s := r.FormValue(name)
	if s == "" {
		return def, nil
	}
	return strconv.ParseBool(s)
}

func ParseMode(r *http.Request) string {
	const name = "mode"
	// "" is allowed mode as some endpoints
	// might equate it with their default mode.
	return r.FormValue(name)
}

type ModuleSpec struct {
	Path, Version string
	ImportedBy    int
}

func ParseCorpusFile(filename string, minImportedByCount int) (ms []ModuleSpec, err error) {
	defer derrors.Wrap(&err, "parseCorpusFile(%q)", filename)
	lines, err := ReadFileLines(filename)
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		var path, vers, imps string
		switch len(fields) {
		case 2: // no version (temporary)
			path = fields[0]
			vers = version.Latest
			imps = fields[1]
		case 3:
			path = fields[0]
			vers = fields[1]
			imps = fields[2]
		default:
			return nil, fmt.Errorf("wrong number of fields on line %q", line)
		}
		n, err := strconv.Atoi(imps)
		if err != nil {
			return nil, fmt.Errorf("%v on line %q", err, line)
		}
		if n >= minImportedByCount {
			ms = append(ms, ModuleSpec{Path: path, Version: vers, ImportedBy: n})
		}
	}
	return ms, nil
}

// ReadFilelines reads and returns the lines from a file.
// Whitespace on each line is trimmed.
// Blank lines and lines beginning with '#' are ignored.
func ReadFileLines(filename string) (lines []string, err error) {
	defer derrors.Wrap(&err, "readFileLines(%q)", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if s.Err() != nil {
		return nil, s.Err()
	}
	return lines, nil
}
