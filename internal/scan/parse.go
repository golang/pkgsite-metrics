// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scan provides functionality for parsing a scan request.
package scan

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/version"
)

// Request contains information passed
// to a scan endpoint.
type Request struct {
	ModuleURLPath
	RequestParams
}

// RequestParams has query parameters for a scan request.
type RequestParams struct {
	ImportedBy int
	Mode       string
	Insecure   bool
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
func ParseRequest(r *http.Request, scanPrefix string) (_ *Request, err error) {
	defer derrors.Wrap(&err, "ParseRequest(%s)", scanPrefix)

	mp, err := ParseModuleURLPath(strings.TrimPrefix(r.URL.Path, scanPrefix))
	if err != nil {
		return nil, err
	}

	rp := RequestParams{ImportedBy: -1} // use -1 to detect missing param (explicit 0 is OK)
	if err := ParseParams(r, &rp); err != nil {
		return nil, err
	}
	if rp.ImportedBy < 0 {
		return nil, errors.New(`missing or negative "importedby" query param`)
	}
	return &Request{
		ModuleURLPath: mp,
		RequestParams: rp,
	}, nil
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

// A ModuleURLPath holds the components of a URL path parsed
// as module, version and suffix.
type ModuleURLPath struct {
	Module  string
	Version string
	Suffix  string
}

// ParseModuleURLPath parse the module path, version and suffix described by
// the argument, which is expected to be a URL path.
// The module and version should have one of the following three forms:
//   - <module>/@v/<version>
//   - <module>@<version>
//   - <module>/@latest
//
// The suffix is the part of the path after the version.
func ParseModuleURLPath(requestPath string) (_ ModuleURLPath, err error) {
	defer derrors.Wrap(&err, "ParseModuleURLPath(%q)", requestPath)

	p := strings.TrimPrefix(requestPath, "/")
	modulePath, versionAndSuffix, found := strings.Cut(p, "@")
	if !found {
		return ModuleURLPath{}, fmt.Errorf("invalid path %q: missing '@'", requestPath)
	}
	modulePath = strings.TrimSuffix(modulePath, "/")
	if modulePath == "" {
		return ModuleURLPath{}, fmt.Errorf("invalid path %q: missing module", requestPath)
	}
	if strings.HasPrefix(versionAndSuffix, "v/") {
		versionAndSuffix = versionAndSuffix[2:]
	}
	// Now versionAndSuffix begins with a version.
	version, suffix, _ := strings.Cut(versionAndSuffix, "/")
	if version == "" {
		return ModuleURLPath{}, fmt.Errorf("invalid path %q: missing version", requestPath)
	}
	if version[0] != 'v' {
		version = "v" + version
	}
	return ModuleURLPath{modulePath, version, suffix}, nil
}

// Path reconstructs a URL path from m.
func (m ModuleURLPath) Path() string {
	p := m.Module + "@" + m.Version
	if m.Suffix != "" {
		p += "/" + m.Suffix
	}
	return p
}

// ParseParams populates the fields of pstruct, which must a pointer to a struct,
// with the form and query parameters of r.
//
// The fields of pstruct must be exported, and each field must be a string, an
// int or a bool. If there is a request parameter corresponding to the
// lower-cased field name, it is parsed according to the field's type and
// assigned to the field. If there is no matching parameter (or it is the empty
// string), the field is not assigned.
//
// For default values or to detect missing parameters, set the struct field
// before calling ParseParams; if there is no matching parameter, the field will
// retain its value.
func ParseParams(r *http.Request, pstruct any) (err error) {
	defer derrors.Wrap(&err, "ParseParams(%q)", r.URL)

	v := reflect.ValueOf(pstruct)
	t := v.Type()
	if t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("need struct pointer, got %T", pstruct)
	}
	t = t.Elem()
	v = v.Elem()

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		paramName := strings.ToLower(f.Name)
		param := r.FormValue(paramName)
		if param == "" {
			// If param is missing, do not set field.
			continue
		}
		pval, err := parseParam(param, f.Type.Kind())
		if err != nil {
			return fmt.Errorf("param %s: %v", paramName, err)
		}
		v.Field(i).Set(reflect.ValueOf(pval))
	}
	return nil
}

func parseParam(param string, kind reflect.Kind) (any, error) {
	switch kind {
	case reflect.String:
		return param, nil
	case reflect.Int:
		return strconv.Atoi(param)
	case reflect.Bool:
		return strconv.ParseBool(param)
	default:
		return nil, fmt.Errorf("cannot parse kind %s", kind)
	}
}