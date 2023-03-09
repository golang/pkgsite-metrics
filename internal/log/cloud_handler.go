// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"os"
	"time"

	"golang.org/x/exp/slog"
)

// NewGoogleCloudHandler returns a Handler that outputs JSON for the Google
// Cloud logging service.
// See https://cloud.google.com/logging/docs/agent/logging/configuration#special-fields
// for treatment of special fields.
func NewGoogleCloudHandler() slog.Handler {
	return slog.HandlerOptions{ReplaceAttr: gcpReplaceAttr, Level: slog.LevelDebug}.
		NewJSONHandler(os.Stderr)
}

func gcpReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case "time":
		if a.Value.Kind() == slog.KindTime {
			a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
		}
	case "msg":
		a.Key = "message"
	case "level":
		a.Key = "severity"
	case "traceID":
		a.Key = "logging.googleapis.com/trace"
	}
	return a
}
