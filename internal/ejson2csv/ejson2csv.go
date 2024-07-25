// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ejson2csv

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// sliceOf converts string/int args into a 5-element slice of string,
// reusing the input slice (pointer) s.
func sliceOf(s *[]string, args ...any) []string {
	*s = (*s)[:0]
	for _, x := range args {
		switch x := x.(type) {
		case int:
			*s = append(*s, strconv.FormatInt(int64(x), 10))
		case string:
			*s = append(*s, x)
		}
	}
	for len(*s) < 5 {
		*s = append(*s, "")
	}
	return *s
}

// Process converts JSON read from r into CSV written to w, filtered
// according to the various flags.  The default is to include only
// diagnostic messages (all false), errors specifies errors,
// others specifies all lines that are neither error nor diagnostics,
// and all means all.  One limits the output to the first line (error,
// diagnostic, or neither) from each module in the JSON stream.
func Process(r io.Reader, w io.Writer, errors, others, all, one bool) {
	var stuff any

	buf, err := io.ReadAll(r)
	must(err)

	err = json.Unmarshal(buf, &stuff)
	must(err)

	slice := stuff.([]any)

	out := csv.NewWriter(w)

	var line []string
	line = sliceOf(&line, "ModulePath", "mpIndex", "Message/error", "meIndex", "Position")
	out.Write(line)

outer:
	for i, a := range slice {
		ma := a.(map[string]any)

		if s, ok := ma["Diagnostics"].([]any); ok {
			// sawDiagnostic indicates non-empty error/message
			// this should always be true here, but just in case, track it.
			sawDiagnostic := false

			for j, d := range s {
				md := d.(map[string]any)
				if m, ok := md["Error"].(string); ok && m != "" {
					// error messages print if errors or all.
					if errors || all {
						out.Write(sliceOf(&line, ma["ModulePath"], i, m, j, md["Position"]))
						if one {
							continue outer
						}
					}
					sawDiagnostic = true
				}
				if m, ok := md["Message"].(string); ok && m != "" {
					// diagnostic messages print if present and either all or not-errors-and-not-others
					if !errors && !others || all {
						out.Write(sliceOf(&line, ma["ModulePath"], i, m, j, md["Position"]))
						if one {
							continue outer
						}
					}
					sawDiagnostic = true
				}
			}
			if sawDiagnostic {
				continue outer
			}
		}
		// Here if no diagnostic message or error lines were printed.
		if others || all {
			out.Write(sliceOf(&line, ma["ModulePath"], i))
		}
	}
	out.Flush()
}
