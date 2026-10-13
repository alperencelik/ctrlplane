package main

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Read-only Prometheus query API paths; nothing that writes, deletes or lists global metadata.
var metricsPaths = regexp.MustCompile(`^/api/v1/(query|query_range|series|labels|label/[a-zA-Z_][a-zA-Z0-9_]*/values|status/buildinfo)$`)

// metricsHandler serves /platform/metrics/api/v1/... (a Prometheus data source URL of
// <endpoint>/platform/metrics) from the platform's VictoriaMetrics, behind this API server's
// authn/authz. Every query is restricted to this tenant's series with
// extra_label=ctrlplane_tenant=<hostNS>; callers' own extra_* parameters are dropped.
func metricsHandler(upstream, hostNS string) (http.Handler, error) {
	base, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: time.Minute}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/platform/metrics")
		if !metricsPaths.MatchString(path) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost { // Grafana POSTs queries as a form
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
		q.Set("extra_label", "ctrlplane_tenant="+hostNS)
		u := *base
		u.Path = strings.TrimSuffix(u.Path, "/") + path
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "metrics store unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}), nil
}
