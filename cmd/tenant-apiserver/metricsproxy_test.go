package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsProxyHandler(t *testing.T) {
	// Stands in for controller-runtime's secure metrics server: TLS, bearer token required.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "up 1\n")
	}))
	defer target.Close()
	proxy := httptest.NewServer(metricsProxyHandler(target.URL+"/metrics",
		func(context.Context) (string, error) { return "t1", nil }, target.Client()))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "up 1") {
		t.Fatalf("got %d %q", resp.StatusCode, b)
	}
}
