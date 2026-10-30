package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

func testDeployment(created time.Time, mutate ...func(*appsv1.Deployment)) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-acme", Name: "ctrl-kubemox", Generation: 1, CreationTimestamp: metav1.NewTime(created),
			Labels: map[string]string{labelController: "kubemox"}, Annotations: map[string]string{"deployment.kubernetes.io/revision": "1"}},
		Spec: appsv1.DeploymentSpec{Replicas: ptr.To[int32](1), Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "controller", Image: "ghcr.io/acme/op:v1", Args: []string{"--leader-elect"},
			Env:       []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "info"}, {Name: "OLD", Value: "x"}, {Name: "KUBECONFIG", Value: kubeconfigPath}},
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")}},
		}}}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 1},
	}
	for _, m := range mutate {
		m(d)
	}
	return d
}

func TestDeploySince(t *testing.T) {
	container := func(d *appsv1.Deployment) *corev1.Container { return &d.Spec.Template.Spec.Containers[0] }
	for _, tc := range []struct {
		name      string
		mutate    func(*appsv1.Deployment)
		kind, msg string
	}{
		{"nothing", func(*appsv1.Deployment) {}, "", ""},
		{"image", func(d *appsv1.Deployment) { container(d).Image = "ghcr.io/acme/op:v2" }, deployChanged, "image ghcr.io/acme/op:v1 → ghcr.io/acme/op:v2"},
		{"limits", func(d *appsv1.Deployment) {
			container(d).Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi"), corev1.ResourceCPU: resource.MustParse("500m")}
		}, deployChanged, "CPU limit none → 500m; memory limit 128Mi → 256Mi"},
		{"args never show", func(d *appsv1.Deployment) { container(d).Args = []string{"--token=s3cret"} }, deployChanged, "args changed"},
		{"env values never show", func(d *appsv1.Deployment) {
			container(d).Env = []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "s3cret"}, {Name: "NEW", Value: "y"}}
		}, deployChanged, "env LOG_LEVEL changed, NEW added, OLD removed"},
		{"probes", func(d *appsv1.Deployment) { container(d).LivenessProbe = &corev1.Probe{PeriodSeconds: 5} }, deployChanged, "probes changed"},
		{"stop", func(d *appsv1.Deployment) { d.Spec.Replicas = ptr.To[int32](0) }, deployStopped, "Stopped"},
		{"restart", func(d *appsv1.Deployment) {
			d.Spec.Template.Annotations = map[string]string{"kubectl.kubernetes.io/restartedAt": "now"}
			d.Annotations["deployment.kubernetes.io/revision"] = "2"
		}, deployRestart, "Restarted"},
		{"a tunnel's env is the platform's", func(d *appsv1.Deployment) {
			container(d).Env = append(container(d).Env, corev1.EnvVar{Name: "HTTPS_PROXY", Value: "socks5://tunnel"})
			d.Annotations["deployment.kubernetes.io/revision"] = "2"
		}, deployPlatform, "Rolled out by the platform (tunnel, certificate or upgrade)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, ok := snapshotOf(testDeployment(time.Now()))
			if !ok {
				t.Fatal("no controller container")
			}
			cur, ok := snapshotOf(testDeployment(time.Now(), tc.mutate))
			if !ok {
				t.Fatal("no controller container")
			}
			if kind, msg := cur.since(old); kind != tc.kind || msg != tc.msg {
				t.Errorf("got %q %q, want %q %q", kind, msg, tc.kind, tc.msg)
			}
		})
	}
}

// The env the platform adds isn't the customer's, or a new tunnel would read as an env change.
func TestDeploySnapshotPlatformEnv(t *testing.T) {
	c := platformv1alpha1.ControllerSpec{Name: "kubemox", Image: "op:v1", Env: []platformv1alpha1.EnvVar{{Name: "MINE", Value: "1"}}}
	ac := (&reconciler{}).controllerDeployment("tenant-acme", "acme", c, &platformv1alpha1.TunnelSpec{Type: "chisel"}, "cert", "", metav1ac.OwnerReference())
	b, err := json.Marshal(ac)
	if err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := json.Unmarshal(b, d); err != nil {
		t.Fatal(err)
	}
	s, ok := snapshotOf(d)
	if !ok || len(s.Env) != 1 || s.Env["MINE"] == "" {
		t.Errorf("snapshot env %v (ok %v), want only MINE", s.Env, ok)
	}
}

func TestDeployObserve(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &deployShipper{last: map[string]deploySnapshot{}}

	// Already there when the shipper first saw it: no change to mark, only something to compare to.
	if l := s.observe(testDeployment(now.Add(-time.Hour)), now); l == nil || l.Kind != deployBaseline {
		t.Fatalf("existing controller: %+v", l)
	}
	if l := s.observe(testDeployment(now.Add(-time.Hour)), now); l != nil {
		t.Errorf("unchanged: %+v", l)
	}

	// A change is one line: not one before the deployment controller saw it, then one for its new revision.
	seen := func(d *appsv1.Deployment) {
		d.Generation = 2
		d.Spec.Template.Spec.Containers[0].Image = "ghcr.io/acme/op:v2"
	}
	if l := s.observe(testDeployment(now.Add(-time.Hour), seen), now); l != nil {
		t.Errorf("before the deployment controller saw it: %+v", l)
	}
	rolled := func(d *appsv1.Deployment) {
		d.Status.ObservedGeneration = 2
		d.Annotations["deployment.kubernetes.io/revision"] = "2"
	}
	l := s.observe(testDeployment(now.Add(-time.Hour), seen, rolled), now)
	if l == nil || l.Kind != deployChanged || l.Msg != "image ghcr.io/acme/op:v1 → ghcr.io/acme/op:v2" {
		t.Fatalf("change: %+v", l)
	}
	if l := s.observe(testDeployment(now.Add(-time.Hour), seen, rolled), now); l != nil {
		t.Errorf("second look at the same change: %+v", l)
	}

	// Back to the old image: the ReplicaSet is reused, but it's a change like any other.
	back := func(d *appsv1.Deployment) {
		d.Generation, d.Status.ObservedGeneration = 3, 3
		d.Annotations["deployment.kubernetes.io/revision"] = "3"
	}
	if l := s.observe(testDeployment(now.Add(-time.Hour), back), now); l == nil || l.Msg != "image ghcr.io/acme/op:v2 → ghcr.io/acme/op:v1" {
		t.Fatalf("rollback: %+v", l)
	}

	if l := s.removed(testDeployment(now.Add(-time.Hour)), now); l == nil || l.Kind != deployRemoved {
		t.Fatalf("removed: %+v", l)
	}
	if l := s.observe(testDeployment(now.Add(-time.Minute)), now); l == nil || l.Kind != deployDeployed || l.Msg != "Deployed ghcr.io/acme/op:v1" {
		t.Fatalf("new controller: %+v", l)
	}

	other := testDeployment(now)
	other.Namespace = "platform-system"
	if l := s.observe(other, now); l != nil {
		t.Errorf("not a tenant's: %+v", l)
	}
}

func TestDeployStored(t *testing.T) {
	snap, _ := json.Marshal(deploySnapshot{Image: "op:v2", Replicas: 1})
	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, l := range []deployLine{
			{Tenant: "tenant-a", Controller: "kept", Kind: deployChanged, Snapshot: string(snap)},
			{Tenant: "tenant-a", Controller: "gone", Kind: deployRemoved},
		} {
			b, _ := json.Marshal(l)
			fmt.Fprintf(w, "%s\n", b)
		}
	}))
	defer vl.Close()
	s := &deployShipper{vl: vl.URL, http: vl.Client()}
	last, err := s.stored(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(last) != 1 || last["tenant-a/kept"].Image != "op:v2" {
		t.Errorf("stored %+v", last)
	}
}

// TestDeployStoredVictoriaLogs runs the real queries, VICTORIALOGS_URL set to an empty store.
func TestDeployStoredVictoriaLogs(t *testing.T) {
	vl := os.Getenv("VICTORIALOGS_URL")
	if vl == "" {
		t.Skip("VICTORIALOGS_URL not set")
	}
	ctx := context.Background()
	s := &deployShipper{vl: vl, http: &http.Client{Timeout: 5 * time.Second}}
	base := time.Now().Add(-time.Minute).UTC()
	snap := func(image string) string {
		b, _ := json.Marshal(deploySnapshot{Image: image, Replicas: 1})
		return string(b)
	}
	lines := []deployLine{
		{Msg: "Deployed", Time: base, Tenant: "tenant-a", Source: "deploys", Controller: "op", Kind: deployDeployed, Snapshot: snap("op:v1")},
		{Msg: "image", Time: base.Add(time.Second), Tenant: "tenant-a", Source: "deploys", Controller: "op", Kind: deployChanged, Snapshot: snap("op:v2")},
		{Msg: "other", Time: base, Tenant: "tenant-b", Source: "deploys", Controller: "op", Kind: deployChanged, Snapshot: snap("b:v1")},
		{Msg: "Deployed", Time: base, Tenant: "tenant-a", Source: "deploys", Controller: "gone", Kind: deployDeployed, Snapshot: snap("g:v1")},
		{Msg: "Removed", Time: base.Add(time.Second), Tenant: "tenant-a", Source: "deploys", Controller: "gone", Kind: deployRemoved},
	}
	if err := vlInsert(ctx, s.http, vl, "ctrlplane_tenant,ctrlplane_source", lines); err != nil {
		t.Fatal(err)
	}
	// Other streams, as the site's log search and the events' resume point see them.
	if err := vlInsert(ctx, s.http, vl, "ctrlplane_tenant,ctrlplane_controller,ctrlplane_pod", []logLine{{Msg: "a log", Time: base, Tenant: "tenant-a", Controller: "op", Pod: "p"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Post(vl+"/internal/force_flush", "", nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		last, err := s.stored(ctx)
		if err != nil {
			return err
		}
		if len(last) != 2 || last["tenant-a/op"].Image != "op:v2" || last["tenant-b/op"].Image != "b:v1" {
			return fmt.Errorf("stored %+v", last)
		}
		return nil
	})

	query := func(q string) string {
		resp, err := http.Post(vl+"/select/logsql/query", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"query": {q}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		dec := json.NewDecoder(resp.Body)
		for dec.More() {
			var r map[string]any
			if err := dec.Decode(&r); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(b, r["_msg"])
		}
		return b.String()
	}
	// The site's marks: this controller, newest first; the store's filter adds the tenant.
	if got, want := query(`{ctrlplane_tenant="tenant-a",ctrlplane_source="deploys"} controller:="op" -kind:=baseline | sort by (_time) desc`), "image\nDeployed\n"; got != want {
		t.Errorf("marks %q, want %q", got, want)
	}
	// A log search stays logs: it filters on the ctrlplane_controller stream field.
	if got, want := query(`{ctrlplane_tenant="tenant-a"} {ctrlplane_controller="op"} (*)`), "a log\n"; got != want {
		t.Errorf("log search %q, want %q", got, want)
	}
}
