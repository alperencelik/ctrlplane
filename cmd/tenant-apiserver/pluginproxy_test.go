package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/request"
)

// hostSeen is what the fake host API server got.
type hostSeen struct {
	method, path, query, accept, contentType, body string
}

func TestPluginProxy(t *testing.T) {
	var seen *hostSeen
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = &hostSeen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Accept"), r.Header.Get("Content-Type"), string(b)}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("watch") == "true":
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, `{"type":"ADDED","object":{"kind":"Gadget","metadata":{"name":"g1","namespace":"plugins-acme"}}}`+"\n")
			_, _ = io.WriteString(w, `{"type":"DELETED","object":{"kind":"Gadget","metadata":{"name":"g1","namespace":"plugins-acme"}}}`+"\n")
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/gadgets"):
			_, _ = io.WriteString(w, `{"kind":"GadgetList","items":[{"metadata":{"name":"g1","namespace":"plugins-acme"},"spec":{"size":12345678901234567890}}]}`)
		case strings.HasSuffix(r.URL.Path, "/missing"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"kind":"Status","code":403,"message":"cannot get resource \"gadgets\" in the namespace \"plugins-acme\""}`)
		default: // echo the object back, as a create does
			_, _ = w.Write(b)
		}
	}))
	defer host.Close()
	u, _ := url.Parse(host.URL)
	next := false
	p := &pluginProxy{next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true }),
		resources: map[schema.GroupResource]bool{{Group: "plugin.example.com", Resource: "gadgets"}: true},
		tenantNS:  "acme", hostNS: "plugins-acme", host: u, transport: http.DefaultTransport}

	do := func(method, target, contentType, accept, body string, info request.RequestInfo) *httptest.ResponseRecorder {
		t.Helper()
		seen, next = nil, false
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		if body == "" {
			r = httptest.NewRequest(method, target, nil)
		}
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Accept", accept)
		r = r.WithContext(request.WithRequestInfo(r.Context(), &info))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}
	gadgets := func(verb, ns, name string) request.RequestInfo {
		return request.RequestInfo{IsResourceRequest: true, Verb: verb, APIGroup: "plugin.example.com", APIVersion: "v1", Namespace: ns, Resource: "gadgets", Name: name}
	}

	// A list in the tenant's namespace: the host's namespace, and back.
	w := do("GET", "/apis/plugin.example.com/v1/namespaces/acme/gadgets?fieldSelector=metadata.namespace%3Dacme&limit=5", "",
		"application/vnd.kubernetes.protobuf, application/json;as=Table;v=v1;g=meta.k8s.io, application/json", "", gadgets("list", "acme", ""))
	if seen == nil || seen.path != "/apis/plugin.example.com/v1/namespaces/plugins-acme/gadgets" {
		t.Fatalf("host got %+v", seen)
	}
	if q, _ := url.ParseQuery(seen.query); q.Get("fieldSelector") != "metadata.namespace=plugins-acme" || q.Get("limit") != "5" {
		t.Errorf("query %q", seen.query)
	}
	if seen.accept != "application/json;as=Table;v=v1;g=meta.k8s.io,application/json" {
		t.Errorf("accept %q: JSON only", seen.accept)
	}
	if b := w.Body.String(); !strings.Contains(b, `"namespace":"acme"`) || strings.Contains(b, "plugins-acme") || !strings.Contains(b, "12345678901234567890") {
		t.Errorf("list back %s", b)
	}

	// By name, as kubectl wait and informers ask: RequestInfo has the name; the host gets a list.
	do("GET", "/apis/plugin.example.com/v1/namespaces/acme/gadgets?fieldSelector=metadata.name%3Dg1&watch=true", "", "", "", gadgets("watch", "acme", "g1"))
	if seen == nil || seen.path != "/apis/plugin.example.com/v1/namespaces/plugins-acme/gadgets" || !strings.Contains(seen.query, "metadata.name%3Dg1") {
		t.Errorf("watch by name: host got %+v", seen)
	}

	// Across namespaces: only to read, and from the host namespace alone.
	if do("GET", "/apis/plugin.example.com/v1/gadgets", "", "", "", gadgets("list", "", "")); seen == nil || seen.path != "/apis/plugin.example.com/v1/namespaces/plugins-acme/gadgets" {
		t.Errorf("cluster-wide list: host got %+v", seen)
	}
	for _, info := range []request.RequestInfo{gadgets("get", "other", "g1"), gadgets("list", "kube-system", ""), gadgets("create", "", ""), gadgets("deletecollection", "", ""), gadgets("get", "acme", "..")} {
		if w := do("GET", "/x", "", "", "", info); w.Code != http.StatusForbidden || seen != nil {
			t.Errorf("%s in %q: %d, host called: %v", info.Verb, info.Namespace, w.Code, seen != nil)
		}
	}

	// Writes: the body's namespace (and same-namespace references) mapped; any other namespace refused.
	w = do("POST", "/apis/plugin.example.com/v1/namespaces/acme/gadgets", "application/json", "application/json",
		`{"metadata":{"name":"g1","namespace":"acme"},"spec":{"ref":{"namespace":"acme"},"none":{"namespace":""}},"status":{"x":{"namespace":"elsewhere"}}}`, gadgets("create", "acme", ""))
	if seen == nil || !strings.Contains(seen.body, `"ref":{"namespace":"plugins-acme"}`) || !strings.Contains(seen.body, `"metadata":{"name":"g1","namespace":"plugins-acme"}`) ||
		!strings.Contains(seen.body, `"status":{"x":{"namespace":"elsewhere"}}`) {
		t.Errorf("create body %+v", seen)
	}
	for ct, body := range map[string]string{
		"application/json":             `{"metadata":{"name":"g1"},"spec":{"secretRef":{"name":"aws","namespace":"plugins-other"}}}`,
		"application/merge-patch+json": `{"spec":{"refs":[{"namespace":"kube-system"}]}}`,
		"application/json-patch+json":  `[{"op":"add","path":"/spec/secretRef/namespace","value":"plugins-other"}]`,
		"application/apply-patch+yaml": "spec:\n  secretRef: {name: aws, namespace: default}\n",
	} {
		if w := do("PATCH", "/apis/plugin.example.com/v1/namespaces/acme/gadgets/g1", ct, "", body, gadgets("patch", "acme", "g1")); w.Code != http.StatusForbidden || seen != nil {
			t.Errorf("%s naming another namespace: %d, host called: %v", ct, w.Code, seen != nil)
		}
	}
	do("PATCH", "/apis/plugin.example.com/v1/namespaces/acme/gadgets/g1", "application/json-patch+json", "",
		`[{"op":"replace","path":"/spec/secretRef/namespace","value":"acme"},{"op":"add","path":"/spec/r","value":{"namespace":"acme"}}]`, gadgets("patch", "acme", "g1"))
	if seen == nil || strings.Count(seen.body, `"plugins-acme"`) != 2 {
		t.Errorf("JSON patch: host got %+v", seen)
	}
	if !strings.Contains(w.Body.String(), `"metadata":{"name":"g1","namespace":"acme"}`) {
		t.Errorf("create back %s", w.Body)
	}
	do("PATCH", "/apis/plugin.example.com/v1/namespaces/acme/gadgets/g1?fieldManager=kubectl", "application/apply-patch+yaml", "application/json",
		"apiVersion: plugin.example.com/v1\nkind: Gadget\nmetadata:\n  name: g1\n  namespace: acme\n", gadgets("patch", "acme", "g1"))
	if seen == nil || seen.path != "/apis/plugin.example.com/v1/namespaces/plugins-acme/gadgets/g1" || seen.contentType != "application/apply-patch+yaml" ||
		!strings.Contains(seen.body, `"namespace":"plugins-acme"`) {
		t.Errorf("apply: host got %+v", seen)
	}
	if w := do("POST", "/apis/plugin.example.com/v1/namespaces/acme/gadgets", "application/cbor", "", "\xa0", gadgets("create", "acme", "")); w.Code != http.StatusUnsupportedMediaType || seen != nil {
		t.Errorf("CBOR: %d (want 415, so clients fall back to JSON)", w.Code)
	}

	// Host errors pass through, without naming the host namespace.
	w = do("GET", "/apis/plugin.example.com/v1/namespaces/acme/gadgets/missing", "", "", "", gadgets("get", "acme", "missing"))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "plugins-acme") || !strings.Contains(w.Body.String(), `\"acme\"`) {
		t.Errorf("status %d %s", w.Code, w.Body)
	}

	// Watch: events streamed, each mapped.
	w = do("GET", "/apis/plugin.example.com/v1/namespaces/acme/gadgets?watch=true", "", "", "", gadgets("watch", "acme", ""))
	sc := bufio.NewScanner(w.Body)
	var events []string
	for sc.Scan() {
		events = append(events, sc.Text())
	}
	if len(events) != 2 || !strings.Contains(events[0], `"type":"ADDED"`) || !strings.Contains(events[1], `"namespace":"acme"`) || strings.Contains(w.Body.String(), "plugins-acme") {
		t.Errorf("watch events %q", events)
	}

	// Anything else: the tenant API server's own.
	if do("GET", "/api/v1/namespaces/acme/configmaps", "", "", "", request.RequestInfo{IsResourceRequest: true, Verb: "list", Namespace: "acme", APIVersion: "v1", Resource: "configmaps"}); !next || seen != nil {
		t.Error("a built-in resource went to the host")
	}
	if do("GET", "/apis/plugin.example.com/v1", "", "", "", request.RequestInfo{Path: "/apis/plugin.example.com/v1"}); !next || seen != nil {
		t.Error("discovery went to the host")
	}
}
