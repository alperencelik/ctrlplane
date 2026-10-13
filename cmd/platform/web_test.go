package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

func TestPublicIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"140.82.112.3": true, "2606:50c0:8000::154": true,
		"127.0.0.1": false, "10.96.0.1": false, "172.18.0.2": false, "192.168.1.10": false,
		"169.254.169.254": false, "100.100.1.1": false, "0.0.0.0": false, "::1": false,
		"fd00::1": false, "fe80::1": false, "::ffff:127.0.0.1": false, "224.0.0.1": false,
	} {
		if got := publicIP(net.ParseIP(ip)); got != want {
			t.Errorf("publicIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestSetForwards(t *testing.T) {
	tun := &platformv1alpha1.TunnelSpec{}
	if msg := setForwards(tun, "proxmox=192.168.0.10:8006\n db = [fd00::1]:5432 \n"); msg != "" {
		t.Fatal(msg)
	}
	got := tun.Forwards
	if len(got) != 2 || got[0].Port != 8006 || got[1].Host != "fd00::1" || got[1].Name != "db" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"proxmox=192.168.0.10", "proxmox", "x=h:port"} {
		if setForwards(&platformv1alpha1.TunnelSpec{}, bad) == "" {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestPodState(t *testing.T) {
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	crashed := corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137}
	for name, tc := range map[string]struct {
		pod                  corev1.Pod
		state, level, detail string
	}{
		"image pull": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: `Back-off pulling image "x"`}}}}}},
			"ImagePullBackOff", "bad", `Back-off pulling image "x"`},
		"crash loop": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{RestartCount: 3,
			LastTerminationState: corev1.ContainerState{Terminated: &crashed},
			State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}},
			"CrashLoopBackOff", "bad", "3 restarts, last exit: OOMKilled (code 137)"},
		"unschedulable": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable", Message: "0/1 nodes are available"}}}},
			"Unschedulable", "bad", "0/1 nodes are available"},
		"creating": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}}},
			"starting", "wait", ""},
		"running": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: ready, ContainerStatuses: []corev1.ContainerStatus{{
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
			"running", "ok", ""},
		"running after a crash": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: ready, ContainerStatuses: []corev1.ContainerStatus{{RestartCount: 1,
			LastTerminationState: corev1.ContainerState{Terminated: &crashed}, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
			"running", "ok", "1 restart, last exit: OOMKilled (code 137)"},
	} {
		state, level, detail := podState(tc.pod)
		if state != tc.state || level != tc.level || detail != tc.detail {
			t.Errorf("%s: got (%q, %q, %q), want (%q, %q, %q)", name, state, level, detail, tc.state, tc.level, tc.detail)
		}
	}
}

func TestAllocate(t *testing.T) {
	q := resource.MustParse
	l := limits{Controllers: 2, CPU: "500m", Memory: "512Mi"}
	mem := func(m string) platformv1alpha1.ControllerSpec {
		return platformv1alpha1.ControllerSpec{Name: m, Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q(m)}}}
	}
	// 100Mi + 412Mi: the whole budget, split as asked; CPU unset: an even share each.
	run, skipped, used := allocate([]platformv1alpha1.ControllerSpec{mem("100Mi"), mem("412Mi")}, l)
	if len(run) != 2 || len(skipped) != 0 || used.Memory().Cmp(q("512Mi")) != 0 || used.Cpu().Cmp(q("500m")) != 0 {
		t.Fatalf("run %d, skipped %v, used %v", len(run), skipped, used)
	}
	if c, r := run[0].Resources.Limits[corev1.ResourceCPU], run[0].Resources.Requests[corev1.ResourceMemory]; c.Cmp(q("250m")) != 0 || r.Cmp(q("32Mi")) != 0 {
		t.Errorf("defaults: cpu limit %v, memory request %v", c, r)
	}
	// Over the budget: the one that doesn't fit doesn't run; nor one beyond the count.
	_, skipped, _ = allocate([]platformv1alpha1.ControllerSpec{mem("400Mi"), mem("200Mi")}, l)
	if fmt.Sprint(skipped) != "[200Mi]" {
		t.Errorf("over budget: skipped %v", skipped)
	}
	_, skipped, _ = allocate([]platformv1alpha1.ControllerSpec{{Name: "a"}, {Name: "b"}, {Name: "c"}}, l)
	if fmt.Sprint(skipped) != "[c]" {
		t.Errorf("over count: skipped %v", skipped)
	}
	// Asking for more than the whole budget gets the whole budget (alone, it fits).
	run, _, _ = allocate([]platformv1alpha1.ControllerSpec{mem("2Gi")}, l)
	if m := run[0].Resources.Limits[corev1.ResourceMemory]; m.Cmp(q("512Mi")) != 0 {
		t.Errorf("capped at the budget: %v", m)
	}
	// No budget: not limited, nothing defaulted.
	run, _, _ = allocate([]platformv1alpha1.ControllerSpec{{Name: "a"}}, limits{})
	if len(run[0].Resources.Limits) != 0 {
		t.Errorf("no budget: %v", run[0].Resources)
	}
}

func TestInRanges(t *testing.T) {
	for ip, want := range map[string]bool{
		"169.254.169.254": true, "10.43.0.1": true, "192.168.0.200": true, "100.100.1.1": true,
		"65.108.1.2": false, "8.8.8.8": false,
	} {
		if got := inRanges(net.ParseIP(ip), privateV4); got != want {
			t.Errorf("%s: got %v", ip, got)
		}
	}
	if !inRanges(net.ParseIP("fe80::1"), privateV6) || inRanges(net.ParseIP("2606:4700::1"), privateV6) {
		t.Error("v6 ranges")
	}
}

func TestSecureHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	secureHeaders(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if h := rec.Header(); h.Get("Content-Security-Policy") != "frame-ancestors 'none'" || h.Get("Strict-Transport-Security") == "" {
		t.Fatalf("headers = %v", h)
	}
}

func TestToast(t *testing.T) {
	for _, c := range []struct{ errMsg, okMsg, want string }{
		{"", "Deployed hello: starting", `{"toast":{"ok":true,"text":"Deployed hello: starting"}}`},
		{"name taken", "Deployed hello", `{"toast":{"ok":false,"text":"name taken"}}`},
		{"", "", ""},
		// Header bytes are read as Latin-1: non-ASCII travels as JSON escapes (an emoji as a surrogate pair).
		{"", "caf\u00e9 \U0001F600", "{\"toast\":{\"ok\":true,\"text\":\"caf\\u00e9 \\ud83d\\ude00\"}}"},
	} {
		rw := httptest.NewRecorder()
		toast(rw, c.errMsg, c.okMsg)
		if got := rw.Header().Get("HX-Trigger"); got != c.want {
			t.Errorf("toast(%q, %q) = %s, want %s", c.errMsg, c.okMsg, got, c.want)
		}
	}
}

func TestLocalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/tenants/alice-dev#controllers": true, "/": true,
		"": false, "https://evil.example/": false, "//evil.example/": false, `/\evil.example`: false, "tenants": false,
	} {
		if got := localPath(p); got != want {
			t.Errorf("localPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestFragment(t *testing.T) {
	served := false
	h := fragment("api", func(http.ResponseWriter, *http.Request, string) { served = true })
	for _, c := range []struct {
		hx   bool
		want string
	}{{true, ""}, {false, "/tenants/alice-dev#api"}} {
		served = false
		mux := http.NewServeMux()
		mux.HandleFunc("GET /tenants/{name}/crds", func(rw http.ResponseWriter, r *http.Request) { h(rw, r, "github:alice") })
		req := httptest.NewRequest(http.MethodGet, "/tenants/alice-dev/crds", nil)
		if c.hx {
			req.Header.Set("HX-Request", "true")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if served != c.hx || rec.Header().Get("Location") != c.want {
			t.Errorf("hx=%v: served=%v location=%q", c.hx, served, rec.Header().Get("Location"))
		}
	}
}

func TestShortName(t *testing.T) {
	for _, tc := range []struct{ user, name, want string }{
		{"github:Alice", "alice-dev", "dev"},
		{"github:Alice", "alice-dev-2", "dev-2"},
		{"github:Bob", "alice-dev", "alice-dev"}, // shared with bob: whose it is stays
		{"github:Alice", "alicedev", "alicedev"},
		{"local:alice@example.com", "alice-prod", "prod"},
	} {
		if got := shortName(tc.user, tc.name); got != tc.want {
			t.Errorf("shortName(%q, %q) = %q, want %q", tc.user, tc.name, got, tc.want)
		}
	}
}

// The CLI's API: an ID token of either client as a bearer, JSON out, no HX-Request needed. The
// session cookie still needs HX-Request for mutations, and fragments still redirect browsers.
func TestBearerJSON(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	const issuer = "https://auth.example/dex"
	w := &web{Client: k8sClient, apiReader: apiReader, issuer: issuer,
		acct:     &accounts{Client: k8sClient, ns: "platform-system", defaultSignup: "open"},
		verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{SkipClientIDCheck: true})}
	token := func(aud string) string {
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
			"preferred_username": "cli", "federated_claims": map[string]string{"connector_id": "github"}})
		enc := base64.RawURLEncoding.EncodeToString
		signed := enc([]byte(`{"alg":"RS256"}`)) + "." + enc(claims)
		sum := sha256.Sum256([]byte(signed))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		return signed + "." + enc(sig)
	}
	do := func(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for i := 0; i < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		w.routes().ServeHTTP(rec, req)
		return rec
	}
	expect := func(what string, rec *httptest.ResponseRecorder, code int, body string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), body) {
			t.Fatalf("%s: %d %s", what, rec.Code, rec.Body)
		}
	}
	cli := []string{"Authorization", "Bearer " + token("ctrlplane-cli"), "Accept", "application/json"}

	expect("login", do("GET", "/login", "", "Accept", "application/json"), 200, `"issuer":"https://auth.example/dex"`)
	expect("create", do("POST", "/tenants", "name=dev", cli...), 200, `{"name":"cli-dev"}`)
	eventually(t, func() error {
		if rec := do("GET", "/tenants", "", cli...); !strings.Contains(rec.Body.String(), `"prefix":"cli"`) || !strings.Contains(rec.Body.String(), `"name":"cli-dev"`) {
			return fmt.Errorf("list: %d %s", rec.Code, rec.Body)
		}
		return nil
	})
	expect("over the limit", do("POST", "/tenants", "name=two", cli...), 400, `"error":"limit reached`)
	expect("site's audience", do("GET", "/tenants", "", "Authorization", "Bearer "+token("ctrlplane-web"), "Accept", "application/json"), 200, "cli-dev")
	expect("other audience", do("GET", "/tenants", "", "Authorization", "Bearer "+token("grafana"), "Accept", "application/json"), 401, "sign in first")
	cookie := "session=" + token("ctrlplane-web")
	expect("cookie without HX-Request", do("POST", "/tenants", "name=dev", "Cookie", cookie), 403, "HX-Request")
	if rec := do("GET", "/tenants", "", "Cookie", cookie); rec.Code != http.StatusFound {
		t.Fatalf("fragment in a browser: %d", rec.Code)
	}
	expect("delete", do("DELETE", "/tenants/cli-dev", "", cli...), 200, `{"name":"cli-dev"}`)
}
