// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements event handlers for logging.
package log

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/logging"
	"golang.org/x/exp/event"
	"golang.org/x/exp/event/severity"
)

// NewLineHandler returns an event Handler that writes log events one per line
// in an easy-to-read format:
//
//	time level message label1=value1 label2=value2 ...
func NewLineHandler(w io.Writer) event.Handler {
	return &lineHandler{w: w}
}

type lineHandler struct {
	mu sync.Mutex // ensure a log line is not interrupted
	w  io.Writer
}

// Event implements event.Handler.Event for log events.
func (h *lineHandler) Event(ctx context.Context, ev *event.Event) context.Context {
	if ev.Kind != event.LogKind {
		return ctx
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	var msg, level string
	var others []string
	for _, lab := range ev.Labels {
		switch lab.Name {
		case "msg":
			msg = lab.String()
		case "level":
			level = strings.ToUpper(lab.String())
		default:
			others = append(others, fmt.Sprintf("%s=%s", lab.Name, lab.String()))
		}
	}
	var s string
	if len(others) > 0 {
		s = " " + strings.Join(others, " ")
	}
	if level != "" {
		level = " " + level
	}
	fmt.Fprintf(h.w, "%s%s %s%s\n", ev.At.Format("2006/01/02 15:04:05"), level, msg, s)
	return ctx
}

type Labels []event.Label

func With(kvs ...interface{}) Labels {
	return Labels(nil).With(kvs...)
}

func (ls Labels) With(kvs ...interface{}) Labels {
	if len(kvs)%2 != 0 {
		panic("args must be key-value pairs")
	}
	for i := 0; i < len(kvs); i += 2 {
		ls = append(ls, pairToLabel(kvs[i].(string), kvs[i+1]))
	}
	return ls
}

func pairToLabel(name string, value interface{}) event.Label {
	if d, ok := value.(time.Duration); ok {
		return event.Duration(name, d)
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		return event.String(name, v.String())
	case reflect.Bool:
		return event.Bool(name, v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return event.Int64(name, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return event.Uint64(name, v.Uint())
	case reflect.Float32, reflect.Float64:
		return event.Float64(name, v.Float())
	default:
		return event.Value(name, value)
	}
}

func (l Labels) logf(ctx context.Context, s severity.Level, format string, args ...interface{}) {
	event.Log(ctx, fmt.Sprintf(format, args...), append(l, s.Label())...)
}

func (l Labels) Debugf(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Debug, format, args...)
}

func (l Labels) Infof(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Info, format, args...)
}

func (l Labels) Warningf(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Warning, format, args...)
}

func (l Labels) Errorf(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Error, format, args...)
}

var (
	mu     sync.Mutex
	logger interface {
		log(context.Context, logging.Severity, interface{})
	} = stdlibLogger{}

	// currentLevel holds current log level.
	// No logs will be printed below currentLevel.
	currentLevel = logging.Default
)

type (
	// traceIDKey is the type of the context key for trace IDs.
	traceIDKey struct{}

	// labelsKey is the type of the context key for labels.
	labelsKey struct{}
)

// Set the log level
func SetLevel(v string) {
	mu.Lock()
	defer mu.Unlock()
	currentLevel = toLevel(v)
}

func getLevel() logging.Severity {
	mu.Lock()
	defer mu.Unlock()
	return currentLevel
}

// NewContextWithTraceID creates a new context from ctx that adds the trace ID.
func NewContextWithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

// NewContextWithLabel creates a new context from ctx that adds a label that will
// appear in the log entry.
func NewContextWithLabel(ctx context.Context, key, value string) context.Context {
	oldLabels, _ := ctx.Value(labelsKey{}).(map[string]string)
	// Copy the labels, to preserve immutability of contexts.
	newLabels := map[string]string{}
	for k, v := range oldLabels {
		newLabels[k] = v
	}
	newLabels[key] = value
	return context.WithValue(ctx, labelsKey{}, newLabels)
}

// stdlibLogger uses the Go standard library logger.
type stdlibLogger struct{}

func (stdlibLogger) log(ctx context.Context, s logging.Severity, payload interface{}) {
	var extras []string
	traceID, _ := ctx.Value(traceIDKey{}).(string) // if not present, traceID is ""
	if traceID != "" {
		extras = append(extras, fmt.Sprintf("traceID %s", traceID))
	}
	if labels, ok := ctx.Value(labelsKey{}).(map[string]string); ok {
		extras = append(extras, fmt.Sprint(labels))
	}
	var extra string
	if len(extras) > 0 {
		extra = " (" + strings.Join(extras, ", ") + ")"
	}
	log.Printf("%s%s: %+v", s, extra, payload)

}

// Infof logs a formatted string at the Info level.
func Infof(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logging.Info, format, args)
}

// Warningf logs a formatted string at the Warning level.
func Warningf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logging.Warning, format, args)
}

// Errorf logs a formatted string at the Error level.
func Errorf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logging.Error, format, args)
}

// Debugf logs a formatted string at the Debug level.
func Debugf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logging.Debug, format, args)
}

// Fatalf logs formatted string at the Critical level followed by exiting the program.
func Fatalf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logging.Critical, format, args)
	die()
}

func logf(ctx context.Context, s logging.Severity, format string, args []interface{}) {
	doLog(ctx, s, fmt.Sprintf(format, args...))
}

// Info logs arg, which can be a string or a struct, at the Info level.
func Info(ctx context.Context, arg interface{}) { doLog(ctx, logging.Info, arg) }

// Warning logs arg, which can be a string or a struct, at the Warning level.
func Warning(ctx context.Context, arg interface{}) { doLog(ctx, logging.Warning, arg) }

// Error logs arg, which can be a string or a struct, at the Error level.
func Error(ctx context.Context, arg interface{}) { doLog(ctx, logging.Error, arg) }

// Debug logs arg, which can be a string or a struct, at the Debug level.
func Debug(ctx context.Context, arg interface{}) { doLog(ctx, logging.Debug, arg) }

// Fatal logs arg, which can be a string or a struct, at the Critical level followed by exiting the program.
func Fatal(ctx context.Context, arg interface{}) {
	doLog(ctx, logging.Critical, arg)
	die()
}

func doLog(ctx context.Context, s logging.Severity, payload interface{}) {
	if getLevel() > s {
		return
	}
	mu.Lock()
	l := logger
	mu.Unlock()
	l.log(ctx, s, payload)
}

func die() {
	os.Exit(1)
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

// IncludeStderr includes the stderr with an *exec.ExitError.
// If err is not an *exec.ExitError, it returns err.Error().
func IncludeStderr(err error) string {
	var eerr *exec.ExitError
	if errors.As(err, &eerr) {
		return fmt.Sprintf("%v: %s", eerr, bytes.TrimSpace(eerr.Stderr))
	}
	return err.Error()
}
