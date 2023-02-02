// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/safehtml/template"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
)

const (
	indexTemplate = "worker.tmpl"
)

type basePage struct {
}

func newBasePage() basePage {
	return basePage{}
}

func (s *Server) loadTemplates() error {
	index, err := s.parseTemplate(template.TrustedSourceFromConstant(indexTemplate))
	if err != nil {
		return err
	}
	s.templates = map[string]*template.Template{
		indexTemplate: index,
	}
	return nil
}

func (s *Server) maybeLoadTemplate(tmplName string) (*template.Template, error) {
	if s.devMode {
		s.mu.Lock()
		defer s.mu.Unlock()
		var err error
		if err = s.loadTemplates(); err != nil {
			return nil, fmt.Errorf("error parsing templates: %v", err)
		}
	}
	return s.templates[tmplName], nil
}

// Parse the template for the status page.
func (s *Server) parseTemplate(filename template.TrustedSource) (*template.Template, error) {
	templatePath := template.TrustedSourceJoin(s.staticPath, filename)
	return template.New(filename.String()).Funcs(template.FuncMap{
		"timefmt":  FormatTime,
		"commasep": func(s []string) string { return strings.Join(s, ", ") },
		"round":    func(n float64) string { return fmt.Sprintf("%.2f", n) },
	}).ParseFilesFromTrustedSources(templatePath)
}

func renderPage(ctx context.Context, w http.ResponseWriter, page interface{}, tmpl *template.Template) (err error) {
	defer derrors.Wrap(&err, "renderPage")
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, page); err != nil {
		return err
	}
	if _, err := io.Copy(w, &buf); err != nil {
		log.Infof(ctx, "Error copying buffer to ResponseWriter: %v", err)
		return err
	}
	return nil
}
