// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"net/http"

	"golang.org/x/pkgsite-metrics/internal/derrors"
)

type IndexPage struct {
	basePage
}

func (s *Server) handleIndexPage(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != "/" {
		return derrors.NotFound
	}
	tmpl, err := s.maybeLoadTemplate(indexTemplate)
	if err != nil {
		return err
	}
	return renderPage(r.Context(), w, s.createIndexPage(), tmpl)
}

func (s *Server) createIndexPage() *IndexPage {
	return &IndexPage{
		basePage: newBasePage(),
	}
}
