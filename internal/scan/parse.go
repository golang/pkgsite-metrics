// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scan provides functionality for parsing a scan request.
package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/version"
)

func ParseOptionalBoolParam(r *http.Request, name string, def bool) (bool, error) {
	s := r.FormValue(name)
	if s == "" {
		return def, nil
	}
	return strconv.ParseBool(s)
}

type ModuleSpec struct {
	Path, Version string
	ImportedBy    int
}

func ParseCorpusFile(filename string, minImports, maxImports int32) (ms []ModuleSpec, err error) {
	defer derrors.Wrap(&err, "ParseCorpusFile(%q)", filename)
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
		n, err := strconv.ParseInt(imps, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("number of imports: invalid integer %q", imps)
		}
		if minImports <= int32(n) && int32(n) <= maxImports {
			ms = append(ms, ModuleSpec{Path: path, Version: vers, ImportedBy: int(n)})
		}
	}
	return ms, nil
}

// ReadFileLines reads and returns the lines from a file.
// Whitespace on each line is trimmed.
// Blank lines and lines beginning with '#' are ignored.
//
// If filename begins "gs://", it is intepreted as a GCS object.
func ReadFileLines(filename string) (lines []string, err error) {
	defer derrors.Wrap(&err, "ReadFileLines(%q)", filename)
	f, err := openFile(context.TODO(), filename)
	if err != nil {
		return nil, fmt.Errorf("openFile(%q): %w", filename, err)
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

func openFile(ctx context.Context, filename string) (io.ReadCloser, error) {
	if !strings.HasPrefix(filename, "gs://") {
		return os.Open(filename)
	}
	url := strings.TrimPrefix(filename, "gs://")
	bucket, object, found := strings.Cut(url, "/")
	if !found {
		return nil, fmt.Errorf("bad GCS url (no slash): %q", filename)
	}
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}
	return c.Bucket(bucket).Object(object).NewReader(ctx)
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
	versionAndSuffix = strings.TrimPrefix(versionAndSuffix, "v/")
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
		paramValue := r.FormValue(paramName)
		if paramValue == "" {
			// If param is missing, do not set field.
			continue
		}
		pval, err := parseParam(paramValue, f.Type.Kind())
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

// FormatParams takes a struct or struct pointer, and returns
// a URL query-param string with the struct field values.
func FormatParams(s any) string {
	v := reflect.ValueOf(s)
	t := v.Type()
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
		v = v.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("need struct or struct pointer, got %T", s))
	}
	var params []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		val := url.QueryEscape(fmt.Sprint(v.Field(i)))
		params = append(params,
			fmt.Sprintf("%s=%s", strings.ToLower(f.Name), val))
	}
	return strings.Join(params, "&")
}
