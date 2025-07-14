// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/jba/slog/withsupport"
)

// LineHandler is a slog.Handler that writes log events one per line
// in an easy-to-read format:
//
//	time level message label1=value1 label2=value2 ...
type LineHandler struct {
	mu   sync.Mutex
	w    io.Writer
	gora *withsupport.GroupOrAttrs
}

func NewLineHandler(w io.Writer) *LineHandler {
	return &LineHandler{w: w}
}

func (h *LineHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (h *LineHandler) WithGroup(name string) slog.Handler {
	return &LineHandler{w: h.w, gora: h.gora.WithGroup(name)}
}

func (h *LineHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &LineHandler{w: h.w, gora: h.gora.WithAttrs(as)}
}

func (h *LineHandler) Handle(ctx context.Context, r slog.Record) error {
	var buf bytes.Buffer
	if !r.Time.IsZero() {
		fmt.Fprintf(&buf, "%s ", r.Time.Format("2006/01/02 15:04:05"))
	}
	fmt.Fprintf(&buf, "%-5s %s", r.Level, r.Message)

	prefix := ""
	for _, ga := range h.gora.Collect() {
		if ga.Group != "" {
			prefix += ga.Group + "."
		} else {
			for _, a := range ga.Attrs {
				writeAttr(&buf, prefix, a)
			}
		}
	}
	r.Attrs(func(a slog.Attr) bool { writeAttr(&buf, prefix, a); return true })
	buf.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}

func writeAttr(w io.Writer, prefix string, a slog.Attr) {
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" {
			prefix = a.Key + "."
		}
		for _, g := range a.Value.Group() {
			writeAttr(w, prefix, g)
		}
	} else if a.Key != "" {
		fmt.Fprintf(w, " %s%s=", prefix, a.Key)
		if a.Value.Kind() == slog.KindString {
			fmt.Fprintf(w, "%q", a.Value)
		} else {
			fmt.Fprintf(w, "%v", a.Value)
		}
	}
}
