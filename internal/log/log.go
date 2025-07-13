// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements logging.
package log

import (
	"context"
	"fmt"
	"log/slog"
)

type loggerKey struct{}

// NewContext adds the logger to the context.
func NewContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// FromContext retrieves a logger from the context. If there is none,
// it returns the default logger.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

func Debug(ctx context.Context, msg string, args ...any) { FromContext(ctx).Debug(msg, args...) }
func Info(ctx context.Context, msg string, args ...any)  { FromContext(ctx).Info(msg, args...) }
func Warn(ctx context.Context, msg string, args ...any)  { FromContext(ctx).Warn(msg, args...) }
func Error(ctx context.Context, msg string, err error, args ...any) {
	args = append([]any{"err", err}, args...)
	FromContext(ctx).Error(msg, args...)
}

func Logf(ctx context.Context, level slog.Level, format string, args ...any) {
	l := FromContext(ctx)
	if l.Enabled(ctx, level) {
		l.Log(ctx, level, fmt.Sprintf(format, args...))
	}
}

func Debugf(ctx context.Context, format string, args ...any) {
	Logf(ctx, slog.LevelDebug, format, args...)
}

func Infof(ctx context.Context, format string, args ...any) {
	Logf(ctx, slog.LevelInfo, format, args...)
}

func Warnf(ctx context.Context, format string, args ...any) {
	Logf(ctx, slog.LevelWarn, format, args...)
}

func Errorf(ctx context.Context, err error, format string, args ...any) {
	level := slog.LevelError
	l := FromContext(ctx)
	if l.Enabled(ctx, level) {
		l.Log(ctx, level, fmt.Sprintf(format, args...), "err", err)
	}
}
