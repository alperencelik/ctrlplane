package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

// Plugins' resources don't live in the tenant's database: each plugin's operator runs once, on
// the host, and the tenant's objects of its types are objects in the host namespace
// plugins-<tenant>. This API server serves the types (crdoverlay.go: discovery, OpenAPI, RBAC)
// and, past authentication and authorization, forwards the resource requests to the host with
// its own ServiceAccount, which the platform allows those resources in that one namespace and
// nothing else. The tenant sees them in its namespace: "namespace" fields are mapped both ways,
// and a write naming any other namespace is refused (the operator, shared, could read another
// tenant's Secrets for it). Tenant admission (its policies, webhooks) doesn't apply to them; the
// host's does (the operator's webhooks, the platform's policies on plugins-* namespaces).
type pluginProxy struct {
	next             http.Handler
	resources        map[schema.GroupResource]bool // the plugins' (namespaced) resources
	tenantNS, hostNS string
	host             *url.URL
	transport        http.RoundTripper
}

const maxPluginBody = 3 << 20 // the API server's own limit for a request body

func newPluginProxy(crds map[string]*apiextensions.CustomResourceDefinition, tenantNS, hostNS string, host *rest.Config) (func(http.Handler) http.Handler, error) {
	u, err := url.Parse(host.Host)
	if err != nil {
		return nil, err
	}
	rt, err := rest.TransportFor(host)
	if err != nil {
		return nil, err
	}
	res := map[schema.GroupResource]bool{}
	for _, crd := range crds {
		res[schema.GroupResource{Group: crd.Spec.Group, Resource: crd.Spec.Names.Plural}] = true
	}
	return func(next http.Handler) http.Handler {
		return &pluginProxy{next: next, resources: res, tenantNS: tenantNS, hostNS: hostNS, host: u, transport: rt}
	}, nil
}

func (p *pluginProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := request.RequestInfoFrom(r.Context())
	if !ok || !info.IsResourceRequest || !p.resources[schema.GroupResource{Group: info.APIGroup, Resource: info.Resource}] {
		p.next.ServeHTTP(w, r)
		return
	}
	gr := schema.GroupResource{Group: info.APIGroup, Resource: info.Resource}
	// Only the tenant's namespace; across namespaces only to read (it's the only one there is).
	// Never a name path.Join would resolve (hostRequest).
	if info.Namespace != p.tenantNS && (info.Namespace != "" || info.Verb != "list" && info.Verb != "watch") ||
		info.Name == "." || info.Name == ".." || info.Subresource == "." || info.Subresource == ".." {
		writeStatus(w, apierrors.NewForbidden(gr, info.Name, fmt.Errorf("a plugin's resources live in namespace %s", p.tenantNS)))
		return
	}
	req, err := p.hostRequest(r, info)
	if err != nil {
		writeStatus(w, err)
		return
	}
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		writeStatus(w, apierrors.NewServiceUnavailable("plugin resources are unavailable: "+err.Error()))
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	if info.Verb == "watch" && resp.StatusCode == http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		dec := json.NewDecoder(resp.Body)
		dec.UseNumber()
		for { // one event per JSON value; written as they come
			var ev any
			if dec.Decode(&ev) != nil {
				return
			}
			b, _ := json.Marshal(p.toTenant(ev))
			if _, err := w.Write(append(b, '\n')); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		if v, err := decodeJSON(body); err == nil {
			body, _ = json.Marshal(p.toTenant(v))
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// hostRequest is r for the host: the same resource in the host namespace, JSON only (the
// namespace mapping reads the bodies), with the ServiceAccount's credentials (transport).
func (p *pluginProxy) hostRequest(r *http.Request, info *request.RequestInfo) (*http.Request, error) {
	u := *p.host
	q := r.URL.Query()
	name := info.Name
	if (info.Verb == "list" || info.Verb == "watch") && q.Has("fieldSelector") {
		name = "" // RequestInfo copies a metadata.name selector here (for RBAC); in the path it'd be a get
	}
	u.Path = path.Join("/apis", info.APIGroup, info.APIVersion, "namespaces", p.hostNS, info.Resource, name, info.Subresource)
	if s := q.Get("fieldSelector"); s != "" {
		sel, err := fields.ParseSelector(s)
		if err != nil {
			return nil, apierrors.NewBadRequest(err.Error())
		}
		sel, _ = sel.Transform(func(f, v string) (string, string, error) {
			if f == "metadata.namespace" && v == p.tenantNS {
				v = p.hostNS
			}
			return f, v, nil
		})
		q.Set("fieldSelector", sel.String())
	}
	u.RawQuery = q.Encode()

	var body io.Reader
	contentType := r.Header.Get("Content-Type")
	if r.Body != nil && r.ContentLength != 0 {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxPluginBody+1))
		if err != nil {
			return nil, apierrors.NewBadRequest(err.Error())
		}
		if len(b) > maxPluginBody {
			return nil, apierrors.NewRequestEntityTooLargeError(fmt.Sprintf("limit is %d bytes", maxPluginBody))
		}
		media, _, _ := mime.ParseMediaType(contentType)
		switch media {
		case "application/apply-patch+yaml": // JSON is YAML too, so it goes on as JSON
			if b, err = yaml.YAMLToJSON(b); err != nil {
				return nil, apierrors.NewBadRequest(err.Error())
			}
		case "application/json", "application/merge-patch+json", "application/json-patch+json":
		default: // CBOR, protobuf: clients fall back to JSON on a 415
			return nil, apierrors.NewGenericServerResponse(http.StatusUnsupportedMediaType, r.Method, schema.GroupResource{}, "", "plugin resources take JSON or YAML", 0, false)
		}
		v, err := decodeJSON(b)
		if err != nil {
			return nil, apierrors.NewBadRequest(err.Error())
		}
		if err := p.toHost(v, media == "application/json-patch+json"); err != nil {
			return nil, apierrors.NewForbidden(schema.GroupResource{Group: info.APIGroup, Resource: info.Resource}, info.Name, err)
		}
		b, _ = json.Marshal(v)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", jsonOnly(r.Header.Get("Accept")))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", r.UserAgent())
	return req, nil
}

// toHost maps a write's "namespace" fields to the host namespace, and refuses any other namespace
// (status aside: it's the operator's). A JSON patch is checked op by op: "namespace" can be the
// last step of its path, or in its value.
func (p *pluginProxy) toHost(v any, jsonPatch bool) error {
	if !jsonPatch {
		if m, ok := v.(map[string]any); ok {
			status := m["status"]
			delete(m, "status")
			defer func() {
				if status != nil {
					m["status"] = status
				}
			}()
		}
		if ns := otherNamespace(v, p.tenantNS); ns != "" {
			return fmt.Errorf("plugin resources may only refer to namespace %s, not %s", p.tenantNS, ns)
		}
		remapNamespace(v, p.tenantNS, p.hostNS)
		return nil
	}
	ops, _ := v.([]any)
	for _, o := range ops {
		op, _ := o.(map[string]any)
		ptr, _ := op["path"].(string)
		if strings.HasPrefix(ptr, "/status") {
			continue
		}
		if strings.HasSuffix(ptr, "/namespace") {
			if s, ok := op["value"].(string); ok {
				if s != p.tenantNS && s != "" {
					return fmt.Errorf("plugin resources may only refer to namespace %s, not %s", p.tenantNS, s)
				}
				if s == p.tenantNS {
					op["value"] = p.hostNS
				}
			}
		}
		if ns := otherNamespace(op["value"], p.tenantNS); ns != "" {
			return fmt.Errorf("plugin resources may only refer to namespace %s, not %s", p.tenantNS, ns)
		}
		remapNamespace(op["value"], p.tenantNS, p.hostNS)
	}
	return nil
}

// otherNamespace is the first "namespace" field in v naming neither ns nor nothing, else "".
func otherNamespace(v any, ns string) string {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if s, ok := x.(string); ok && k == "namespace" && s != ns && s != "" {
				return s
			}
			if o := otherNamespace(x, ns); o != "" {
				return o
			}
		}
	case []any:
		for _, x := range v {
			if o := otherNamespace(x, ns); o != "" {
				return o
			}
		}
	}
	return ""
}

// toTenant maps a host response (object, list, table, watch event, Status) to the tenant's namespace.
func (p *pluginProxy) toTenant(v any) any {
	remapNamespace(v, p.hostNS, p.tenantNS)
	if m, ok := v.(map[string]any); ok && m["kind"] == "Status" {
		if s, ok := m["message"].(string); ok {
			m["message"] = strings.ReplaceAll(s, `"`+p.hostNS+`"`, `"`+p.tenantNS+`"`)
		}
	}
	return v
}

// remapNamespace replaces every "namespace": from with to, at any depth: objects' metadata,
// lists' items, tables' rows, watch events, and same-namespace references in specs.
func remapNamespace(v any, from, to string) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if s, ok := x.(string); ok && k == "namespace" && s == from {
				v[k] = to
				continue
			}
			remapNamespace(x, from, to)
		}
	case []any:
		for _, x := range v {
			remapNamespace(x, from, to)
		}
	}
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // int64s (resourceVersion is a string, but specs have big numbers too)
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

// jsonOnly keeps the JSON entries of an Accept header (tables included), else plain JSON.
func jsonOnly(accept string) string {
	var keep []string
	for _, a := range strings.Split(accept, ",") {
		if strings.HasPrefix(strings.TrimSpace(a), "application/json") {
			keep = append(keep, strings.TrimSpace(a))
		}
	}
	if len(keep) == 0 {
		return "application/json"
	}
	return strings.Join(keep, ",")
}

func writeStatus(w http.ResponseWriter, err error) {
	var s apierrors.APIStatus
	if !errors.As(err, &s) {
		s = apierrors.NewInternalError(err)
	}
	st := s.Status()
	st.Kind, st.APIVersion = "Status", "v1"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(int(st.Code))
	_ = json.NewEncoder(w).Encode(st)
}
