package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// metricsScraperSA is the tenant service account whose tokens scrape HTTPS metrics endpoints;
// the tenant bootstrap adds GET /metrics to the namespace access every service account there has.
const metricsScraperSA = "ctrlplane-metrics"

// metricsProxy is the sidecar for controllers that serve metrics over HTTPS behind
// controller-runtime's authn/authz filter (`tenant-apiserver metrics-proxy <listen> <target>
// <kubeconfig> <namespace>`): it serves the target's metrics as plain HTTP on listen, for the
// platform's scraper, presenting a short-lived token for metricsScraperSA that the controller
// checks against its own (the tenant's) API server.
func metricsProxy(listen, target, kubeconfig, namespace string) error {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var token string
	var expires time.Time
	tokenFn := func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Until(expires) > 10*time.Minute {
			return token, nil
		}
		ttl := int64(3600)
		tr, err := cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, metricsScraperSA,
			&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &ttl}}, metav1.CreateOptions{})
		if err != nil {
			return "", err
		}
		token, expires = tr.Status.Token, tr.Status.ExpirationTimestamp.Time
		return token, nil
	}
	// The target is this pod's own loopback, where controller-runtime serves a self-signed cert.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	log.Printf("serving %s on %s as %s/%s", target, listen, namespace, metricsScraperSA)
	return http.ListenAndServe(listen, metricsProxyHandler(target, tokenFn, client))
}

func metricsProxyHandler(target string, tokenFn func(context.Context) (string, error), client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := tokenFn(r.Context())
		if err != nil {
			http.Error(w, "token: "+err.Error(), http.StatusBadGateway)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", r.Header.Get("Accept"))
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}
