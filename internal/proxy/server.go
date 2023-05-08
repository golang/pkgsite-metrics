// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"

	"golang.org/x/pkgsite-metrics/internal/log"
)

// ServeDisablingFetch returns a server that proxies requests to proxy.golang.org,
// adding the Disable-Fetch header to prevent the proxy from fetching old modules.
func ServeDisablingFetch() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := proxyRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Errorf(r.Context(), err, "ServeDisablingFetch: io.Copy")
		}
	}))
}

func proxyRequest(r *http.Request) (*http.Response, error) {
	url := "https://proxy.golang.org" + r.URL.Path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(DisableFetchHeader, "true")
	return http.DefaultClient.Do(req)
}
