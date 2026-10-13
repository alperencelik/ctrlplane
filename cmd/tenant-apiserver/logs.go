package main

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Read-only LogsQL query API paths of VictoriaLogs; no insert, delete or tail.
var logsPaths = regexp.MustCompile(`^/select/logsql/(query|hits|field_names|field_values|stream_field_names|stream_field_values|streams|stats_query|stats_query_range)$`)

// logsHandler serves /platform/logs/select/logsql/... (a VictoriaLogs data source URL of
// <endpoint>/platform/logs) from the platform's VictoriaLogs, behind this API server's
// authn/authz. Every query only sees this tenant's streams: extra_stream_filters is set to
// {ctrlplane_tenant="<hostNS>"} (ANDed with the query), and callers' extra_* are dropped.
func logsHandler(upstream, hostNS string) (http.Handler, error) {
	base, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: time.Minute}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/platform/logs")
		if !logsPaths.MatchString(path) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := url.Values{}
		for k, v := range r.Form {
			if !strings.HasPrefix(k, "extra_") {
				q[k] = v
			}
		}
		q.Set("extra_stream_filters", `{ctrlplane_tenant="`+hostNS+`"}`)
		if path == "/select/logsql/query" && q.Get("limit") == "" {
			q.Set("limit", "1000") // a bare "*" would otherwise stream everything
		}
		u := *base
		u.Path = strings.TrimSuffix(u.Path, "/") + path
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.String(), strings.NewReader(q.Encode()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "logs store unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}), nil
}
