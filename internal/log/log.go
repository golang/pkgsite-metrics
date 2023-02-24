// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements logging.
package log

import (
	"context"
	"fmt"
	"log"
	"strings"

	"cloud.google.com/go/logging"
	"golang.org/x/exp/slog"
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
	FromContext(ctx).Error(msg, err, args...)
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
		l.Log(ctx, level, fmt.Sprintf(format, args...), slog.ErrorKey, err)
	}
}

// toLevel returns the logging.Severity for a given string.
// Possible input values are "", "debug", "info", "warning", "error", "fatal".
// In case of invalid string input, it maps to DefaultLevel.
func toLevel(v string) logging.Severity {
	v = strings.ToLower(v)

	switch v {
	case "":
		// default log level will print everything.
		return logging.Default
	case "debug":
		return logging.Debug
	case "info":
		return logging.Info
	case "warning":
		return logging.Warning
	case "error":
		return logging.Error
	case "fatal":
		return logging.Critical
	}

	// Default log level in case of invalid input.
	log.Printf("Error: %s is invalid LogLevel. Possible values are [debug, info, warning, error, fatal]", v)
	return logging.Default
}
