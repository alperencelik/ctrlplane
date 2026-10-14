package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
	"github.com/alperencelik/ctrlplane/pkg/pki"
)

// The envtest suite: a real API server (no kubelet, no garbage collector) with the generated
// CRDs, and the Tenant controller running against it. It holds this package's TestMain, so all
// of its tests need the envtest binaries. `make test` downloads the binaries.

var (
	k8sClient client.Client // the manager's: reads from its cache
	apiReader client.Reader // uncached
	restCfg   *rest.Config  // the test API server, as admin
)

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

func runSuite(m *testing.M) int {
	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.Level(zapcore.ErrorLevel)))
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: firstEnvtestBinaryDir(),
	}
	cfg, err := env.Start()
	restCfg = cfg
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest (run `make test`, or `make setup-envtest` for IDEs):", err)
		return 1
	}
	defer func() { _ = env.Stop() }()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	k8sClient = mgr.GetClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	direct, _ := client.New(cfg, client.Options{Scheme: scheme})
	apiReader = direct
	// The chart's admission policy (deleting a Tenant needs a confirmation annotation), as shipped.
	policy, err := os.ReadFile(filepath.Join("..", "..", "config", "policy", "tenant-delete-policy.yaml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, doc := range strings.Split(string(policy), "\n---\n") {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil || direct.Create(ctx, u) != nil {
			fmt.Fprintln(os.Stderr, "admission policy:", err)
			return 1
		}
	}
	for _, o := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "platform-system"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "platform-system", Name: "regcred"}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"ghcr.io":{"auth":"djE="}}}`)}},
	} {
		if err := direct.Create(ctx, o); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	err = (&reconciler{
		Client:         mgr.GetClient(),
		acct:           &accounts{Client: mgr.GetClient(), ns: "platform-system", defaultSignup: "open"},
		platformNS:     "platform-system",
		apiserverImage: "tenant-apiserver:test",
		pullSecrets:    []string{"regcred"},
		apiserverResources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
		tunnelResources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")}},
		storageSize:     resource.MustParse("2Gi"),
		chiselImage:     "chisel:test",
		workers:         4, // as deployed: tests reconcile tenants in parallel
		endpointPort:    "443",
	}).setupWithManager(mgr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	go func() { _ = mgr.Start(ctx) }()
	return m.Run()
}

// firstEnvtestBinaryDir finds binaries from `make setup-envtest` (bin/k8s/<version>), so the
// tests also run from an IDE; KUBEBUILDER_ASSETS takes precedence.
func firstEnvtestBinaryDir() string {
	entries, _ := os.ReadDir(filepath.Join("..", "..", "bin", "k8s"))
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join("..", "..", "bin", "k8s", e.Name())
		}
	}
	return ""
}

// eventually retries check until it returns nil or 20s pass.
func eventually(t *testing.T, check func() error) {
	t.Helper()
	var err error
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if err = check(); err == nil {
			return
		}
	}
	t.Fatal(err)
}

func TestTenantLifecycle(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}, Spec: platformv1alpha1.TenantSpec{
		Owners:      []string{"github:alice"},
		Controllers: []platformv1alpha1.ControllerSpec{{Name: "vm-watcher", Image: "kubectl:test"}},
	}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	ns := "tenant-acme"

	// Everything a tenant gets, and its status.
	eventually(t, func() error {
		for _, o := range []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
			&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "apiserver"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "apiserver"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "apiserver-pki"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "platform-system", Name: "acme-tenant-pki"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctrl-vm-watcher-kubeconfig"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctrl-vm-watcher"}},
			&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tenant-isolation"}},
			&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tenant-egress"}},
		} {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(o), o); err != nil {
				return fmt.Errorf("%T %s: %w", o, o.GetName(), err)
			}
		}
		got := &platformv1alpha1.Tenant{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tenant), got); err != nil {
			return err
		}
		if got.Status.ID != tenantID(got.UID) || got.Status.Endpoint != "https://apiserver.tenant-acme.svc:6443" {
			return fmt.Errorf("status = %+v", got.Status)
		}
		return nil
	})

	// Controllers run hardened, with the account's caps and the tenant's kubeconfig.
	dep := &appsv1.Deployment{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctrl-vm-watcher"}, dep); err != nil {
		t.Fatal(err)
	}
	pod := dep.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.Containers[0].Resources.Limits.Cpu().IsZero() {
		t.Errorf("controller pod not hardened or uncapped: %+v", pod)
	}
	if !slices.ContainsFunc(pod.Containers[0].Env, func(e corev1.EnvVar) bool { return e.Name == "WATCH_NAMESPACE" && e.Value == "acme" }) {
		t.Errorf("WATCH_NAMESPACE not set: %v", pod.Containers[0].Env)
	}
	// Its cert carries ControllerGroup: the tenant API server's full access is for this group only,
	// not for every ServiceAccount in the namespace.
	kc := &corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctrl-vm-watcher-kubeconfig"}, kc); err != nil {
		t.Fatal(err)
	}
	if b, _ := pem.Decode(pki.KubeconfigCert(kc.Data["kubeconfig"])); b == nil {
		t.Fatal("no client cert in the controller's kubeconfig")
	} else if c, err := x509.ParseCertificate(b.Bytes); err != nil || !slices.Contains(c.Subject.Organization, pki.ControllerGroup) {
		t.Errorf("controller cert groups = %v (%v), want %s among them", c.Subject.Organization, err, pki.ControllerGroup)
	}

	// A suspended owner loses API access: the User watch re-reconciles the tenant.
	acct := &accounts{Client: k8sClient, ns: "platform-system"}
	if err := acct.putUser(ctx, "github:alice", statusSuspended, platformv1alpha1.Limits{CPU: "100m", Memory: "64Mi"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		sts := &appsv1.StatefulSet{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "apiserver"}, sts); err != nil {
			return err
		}
		if args := sts.Spec.Template.Spec.Containers[0].Args; !slices.Contains(args, "--tenant-owners=") {
			return fmt.Errorf("owners still set: %v", args)
		}
		return nil
	})

	// A removed controller is pruned, with its kubeconfig.
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Spec.Controllers = nil
	if err := k8sClient.Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		for _, o := range []client.Object{
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctrl-vm-watcher"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctrl-vm-watcher-kubeconfig"}},
		} {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(o), o); !apierrors.IsNotFound(err) {
				return fmt.Errorf("%s still there (%v)", o.GetName(), err)
			}
		}
		return nil
	})
}

// The generated CRD keeps the hand-written schema's rules.
func TestTenantValidation(t *testing.T) {
	ctx := context.Background()
	for name, tenant := range map[string]*platformv1alpha1.Tenant{
		"name too long": {ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 51)}},
		"bad owner":     {ObjectMeta: metav1.ObjectMeta{Name: "v1"}, Spec: platformv1alpha1.TenantSpec{Owners: []string{"alice"}}},
		"reserved forward": {ObjectMeta: metav1.ObjectMeta{Name: "v2"}, Spec: platformv1alpha1.TenantSpec{Tunnel: &platformv1alpha1.TunnelSpec{
			Type: "chisel", Forwards: []platformv1alpha1.ForwardSpec{{Name: "apiserver", Host: "10.0.0.1", Port: 443}}}}},
		"unknown tunnel": {ObjectMeta: metav1.ObjectMeta{Name: "v3"}, Spec: platformv1alpha1.TenantSpec{Tunnel: &platformv1alpha1.TunnelSpec{Type: "wireguard"}}},
		"metrics scheme": {ObjectMeta: metav1.ObjectMeta{Name: "v4"}, Spec: platformv1alpha1.TenantSpec{Controllers: []platformv1alpha1.ControllerSpec{{
			Name: "c", Image: "i", Metrics: &platformv1alpha1.MetricsSpec{Port: 8443, Scheme: "grpc"}}}}},
		"probe host": {ObjectMeta: metav1.ObjectMeta{Name: "v5"}, Spec: platformv1alpha1.TenantSpec{Controllers: []platformv1alpha1.ControllerSpec{{
			Name: "c", Image: "i", LivenessProbe: &platformv1alpha1.Probe{Probe: corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Host: "192.168.0.1", Port: intstr.FromInt32(80)}}}}}}}},
	} {
		if err := k8sClient.Create(ctx, tenant); !apierrors.IsInvalid(err) {
			t.Errorf("%s: want Invalid, got %v", name, err)
		}
	}
}

// A status write (the reconciler's) between the site's read and its update must not fail the
// owner's edit; a concurrent spec edit still does.
func TestUpdateAfterStatusWrite(t *testing.T) {
	ctx := context.Background()
	w := &web{Client: k8sClient, apiReader: apiReader}
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "racy"}, Spec: platformv1alpha1.TenantSpec{Owners: []string{"github:alice"}}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	read := func() *platformv1alpha1.Tenant {
		got := &platformv1alpha1.Tenant{}
		if err := apiReader.Get(ctx, client.ObjectKeyFromObject(tenant), got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	edit := read()
	status := read()
	status.Status.Tunnel = "https://changed.example" // bumps resourceVersion, not generation
	if err := k8sClient.Status().Update(ctx, status); err != nil {
		t.Fatal(err)
	}
	edit.Spec.Tunnel = &platformv1alpha1.TunnelSpec{Type: "chisel"}
	if msg := w.update(ctx, edit); msg != "" {
		t.Fatalf("edit after a status write: %s", msg)
	}
	if read().Spec.Tunnel == nil {
		t.Fatal("edit not stored")
	}

	stale := read()
	other := read()
	other.Spec.Owners = append(other.Spec.Owners, "github:bob")
	if err := k8sClient.Update(ctx, other); err != nil {
		t.Fatal(err)
	}
	stale.Spec.Tunnel = nil
	if msg := w.update(ctx, stale); msg != "the tenant changed meanwhile, try again" {
		t.Fatalf("concurrent spec edit: got %q", msg)
	}
}

// Pull secrets reach the pods whose images the platform chooses, never a controller's (the kubelet
// would use them for the tenant's image too), and follow rotation of the source Secret.
func TestPullSecrets(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "pulls"}, Spec: platformv1alpha1.TenantSpec{
		Controllers: []platformv1alpha1.ControllerSpec{{Name: "c", Image: "ghcr.io/someone/else:private"}},
	}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	ns := "tenant-pulls"
	copyHas := func(want string) func() error {
		return func() error {
			s := &corev1.Secret{}
			if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "regcred"}, s); err != nil {
				return err
			}
			if got := string(s.Data[corev1.DockerConfigJsonKey]); s.Type != corev1.SecretTypeDockerConfigJson || !strings.Contains(got, want) {
				return fmt.Errorf("copy: %s %s", s.Type, got)
			}
			return nil
		}
	}
	eventually(t, copyHas("djE="))
	eventually(t, func() error {
		sts := &appsv1.StatefulSet{}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "apiserver"}, sts); err != nil {
			return err
		}
		if ps := sts.Spec.Template.Spec.ImagePullSecrets; len(ps) != 1 || ps[0].Name != "regcred" {
			return fmt.Errorf("apiserver imagePullSecrets = %v", ps)
		}
		dep := &appsv1.Deployment{}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctrl-c"}, dep); err != nil {
			return err
		}
		if ps := dep.Spec.Template.Spec.ImagePullSecrets; len(ps) != 0 {
			t.Fatalf("controller pod got the platform's pull secrets: %v", ps)
		}
		return nil
	})

	src := &corev1.Secret{}
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: "platform-system", Name: "regcred"}, src); err != nil {
		t.Fatal(err)
	}
	src.Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":{"ghcr.io":{"auth":"djI="}}}`)
	if err := k8sClient.Update(ctx, src); err != nil {
		t.Fatal(err)
	}
	eventually(t, copyHas("djI="))

	// A copy of a pull secret no longer configured (e.g. a replaced token) is deleted.
	stale := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "old-regcred", Labels: map[string]string{labelPullSecret: "true"}},
		Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)}}
	if err := k8sClient.Create(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if err := apiReader.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Annotations = map[string]string{"touch": "1"} // reconcile
	if err := k8sClient.Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		if err := apiReader.Get(ctx, client.ObjectKeyFromObject(stale), &corev1.Secret{}); !apierrors.IsNotFound(err) {
			return fmt.Errorf("stale copy still there (%v)", err)
		}
		return nil
	})
	eventually(t, copyHas("djI=")) // the configured one stays
}

// A controller's probes and its own registry credentials reach its pod; probe hosts never do.
func TestControllerProbesAndRegistry(t *testing.T) {
	ctx := context.Background()
	live := &platformv1alpha1.Probe{Probe: corev1.Probe{ProbeHandler: corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8081)}}, PeriodSeconds: 7}}
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "probes"}, Spec: platformv1alpha1.TenantSpec{
		Controllers: []platformv1alpha1.ControllerSpec{{Name: "c", Image: "ghcr.io/me/private:v1", LivenessProbe: live, ImagePullSecrets: []string{"c"}}},
	}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		dep := &appsv1.Deployment{}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: "tenant-probes", Name: "ctrl-c"}, dep); err != nil {
			return err
		}
		pod := dep.Spec.Template.Spec
		if ps := pod.ImagePullSecrets; len(ps) != 1 || ps[0].Name != "registry-c" {
			t.Fatalf("imagePullSecrets = %v, want only registry-c", ps)
		}
		if p := pod.Containers[0].LivenessProbe; p == nil || p.HTTPGet == nil || p.HTTPGet.Path != "/healthz" || p.PeriodSeconds != 7 {
			t.Fatalf("livenessProbe = %+v", p)
		}
		if !slices.Contains(pod.Containers[0].Env, corev1.EnvVar{Name: "HOME", Value: "/var/run/tenant"}) {
			t.Fatalf("env = %v, want HOME=/var/run/tenant", pod.Containers[0].Env)
		}
		return nil
	})

	// Stored before the CRD rejected hosts: the pod still never gets one.
	host := &platformv1alpha1.Probe{Probe: corev1.Probe{ProbeHandler: corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{Host: "192.168.0.1", Port: intstr.FromInt32(80)}, TCPSocket: &corev1.TCPSocketAction{Host: "10.0.0.1"}}}}
	if p := probe(host); p.HTTPGet.Host != nil || p.TCPSocket.Host != nil {
		t.Fatalf("probe kept a host: %+v %+v", p.HTTPGet, p.TCPSocket)
	}
}

// A restart (the site's Restart button) survives the reconciler re-applying the deployment.
func TestRestartController(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "restart"}, Spec: platformv1alpha1.TenantSpec{
		Controllers: []platformv1alpha1.ControllerSpec{{Name: "c", Image: "ghcr.io/me/op:v1"}}}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKey{Namespace: "tenant-restart", Name: "ctrl-c"}
	eventually(t, func() error { return apiReader.Get(ctx, key, &appsv1.Deployment{}) })
	if err := restartDeployment(ctx, k8sClient, key.Namespace, key.Name); err != nil {
		t.Fatal(err)
	}
	if err := apiReader.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Spec.Controllers[0].Image = "ghcr.io/me/op:v2"
	if err := k8sClient.Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		dep := &appsv1.Deployment{}
		if err := apiReader.Get(ctx, key, dep); err != nil {
			return err
		}
		if img := dep.Spec.Template.Spec.Containers[0].Image; img != "ghcr.io/me/op:v2" {
			return fmt.Errorf("image = %s, want v2", img)
		}
		if dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] == "" {
			t.Fatalf("restartedAt gone after reconcile: %v", dep.Spec.Template.Annotations)
		}
		return nil
	})
}

// A stopped controller's Deployment is scaled to 0, and back to 1 when it's started again.
func TestStopController(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "stop"}, Spec: platformv1alpha1.TenantSpec{
		Controllers: []platformv1alpha1.ControllerSpec{{Name: "c", Image: "ghcr.io/me/op:v1", Stopped: true}}}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	replicas := func(want int32) {
		eventually(t, func() error {
			dep := &appsv1.Deployment{}
			if err := apiReader.Get(ctx, client.ObjectKey{Namespace: "tenant-stop", Name: "ctrl-c"}, dep); err != nil {
				return err
			}
			if *dep.Spec.Replicas != want {
				return fmt.Errorf("replicas = %d, want %d", *dep.Spec.Replicas, want)
			}
			return nil
		})
	}
	replicas(0)
	if err := apiReader.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Spec.Controllers[0].Stopped = false
	if err := k8sClient.Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	replicas(1)
}

// A controller's webhooks get a Service on 443 and a cert from the tenant CA for the name the
// tenant API server checks, mounted where controller-runtime looks; both go with the webhook.
func TestControllerWebhook(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "hooks"}, Spec: platformv1alpha1.TenantSpec{
		Controllers: []platformv1alpha1.ControllerSpec{{Name: "c", Image: "op:v1", Webhook: &platformv1alpha1.WebhookSpec{}}},
	}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	ns, key := "tenant-hooks", client.ObjectKey{Namespace: "tenant-hooks", Name: "ctrl-c-webhook"}
	eventually(t, func() error {
		svc, s, dep, ca := &corev1.Service{}, &corev1.Secret{}, &appsv1.Deployment{}, &corev1.Secret{}
		for _, g := range []struct {
			k client.ObjectKey
			o client.Object
		}{{key, svc}, {key, s}, {client.ObjectKey{Namespace: ns, Name: "ctrl-c"}, dep}, {client.ObjectKey{Namespace: "platform-system", Name: "hooks-tenant-pki"}, ca}} {
			if err := apiReader.Get(ctx, g.k, g.o); err != nil {
				return err
			}
		}
		if p := svc.Spec.Ports; len(p) != 1 || p[0].Port != 443 || p[0].TargetPort.IntVal != 9443 || svc.Spec.Selector[labelController] != "c" {
			t.Fatalf("service = %+v", svc.Spec)
		}
		b, _ := pem.Decode(s.Data[corev1.TLSCertKey])
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(ca.Data["ca.crt"])
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: "ctrl-c-webhook.hooks.svc", Roots: roots}); err != nil {
			t.Fatalf("webhook cert: %v", err)
		}
		pod := dep.Spec.Template.Spec
		if !slices.ContainsFunc(pod.Containers[0].VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == "webhook-cert" && m.MountPath == webhookCertDir }) ||
			dep.Spec.Template.Annotations[webhookCertAnno] != certHash(s.Data[corev1.TLSCertKey]) {
			t.Fatalf("pod = %+v", dep.Spec.Template)
		}
		return nil
	})

	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Spec.Controllers[0].Webhook = nil
	if err := k8sClient.Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		for _, o := range []client.Object{&corev1.Service{}, &corev1.Secret{}} {
			if err := apiReader.Get(ctx, key, o); !apierrors.IsNotFound(err) {
				return fmt.Errorf("%T still there (%v)", o, err)
			}
		}
		return nil
	})
}

// Every container the platform runs for a tenant has requests/limits; the API server's PVC has
// the configured size.
func TestTenantResources(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "sized"}, Spec: platformv1alpha1.TenantSpec{
		Tunnel: &platformv1alpha1.TunnelSpec{Type: "chisel", Forwards: []platformv1alpha1.ForwardSpec{{Name: "db", Host: "10.0.0.5", Port: 5432}}},
	}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	ns := "tenant-sized"
	mem := func(c corev1.Container) string { return c.Resources.Limits.Memory().String() }
	eventually(t, func() error {
		sts, tun := &appsv1.StatefulSet{}, &appsv1.Deployment{}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "apiserver"}, sts); err != nil {
			return err
		}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "tunnel"}, tun); err != nil {
			return err
		}
		c := tun.Spec.Template.Spec.Containers
		got := fmt.Sprintf("apiserver=%s pvc=%s tunnel=%s forward=%s", mem(sts.Spec.Template.Spec.Containers[0]),
			sts.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests.Storage(), mem(c[0]), mem(c[len(c)-1]))
		if want := "apiserver=1Gi pvc=2Gi tunnel=256Mi forward=256Mi"; got != want || len(c) != 2 {
			return fmt.Errorf("got %s (%d containers), want %s", got, len(c), want)
		}
		return nil
	})
}

// A StatefulSet's claim template can't change: an existing one keeps its size and class.
func TestAPIServerClaimKeepsExisting(t *testing.T) {
	ctx := context.Background()
	if err := k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "claim-test"}}); err != nil {
		t.Fatal(err)
	}
	fast, labels := "fast", map[string]string{"app": "apiserver"}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "claim-test", Name: "apiserver"}, Spec: appsv1.StatefulSetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: labels},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "i"}}}},
		VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}, Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: &fast,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("5Gi")}}}}},
	}}
	if err := k8sClient.Create(ctx, sts); err != nil {
		t.Fatal(err)
	}
	r := &reconciler{Client: k8sClient, storageSize: resource.MustParse("1Gi")}
	eventually(t, func() error { // the cache sees the new StatefulSet
		claim, err := r.apiserverClaim(ctx, "claim-test")
		if err != nil {
			return err
		}
		if got := fmt.Sprintf("%s %s", claim.Resources.Requests.Storage(), ptr.Deref(claim.StorageClassName, "")); got != "5Gi fast" {
			return fmt.Errorf("claim = %s, want the existing 5Gi fast", got)
		}
		return nil
	})
	claim, err := r.apiserverClaim(ctx, "no-such-ns")
	if err != nil || claim.Resources.Requests.Storage().String() != "1Gi" || claim.StorageClassName != nil {
		t.Fatalf("new claim = %+v, %v; want 1Gi, default class", claim, err)
	}
}

// Tenant namespaces enforce Pod Security "restricted": nothing runs less confined than the
// platform's own pods.
func TestTenantPodSecurity(t *testing.T) {
	ctx := context.Background()
	if err := k8sClient.Create(ctx, &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "psa"}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		ns := &corev1.Namespace{}
		if err := apiReader.Get(ctx, client.ObjectKey{Name: "tenant-psa"}, ns); err != nil {
			return err
		}
		if ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
			return fmt.Errorf("labels = %v", ns.Labels)
		}
		return nil
	})
	privileged := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-psa", Name: "escape"}, Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "c", Image: "i", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}}}
	if err := k8sClient.Create(ctx, pod); !apierrors.IsForbidden(err) {
		t.Fatalf("privileged pod in a tenant namespace: want Forbidden, got %v", err)
	}
}

// Deleting a Tenant needs the confirmation annotation (the chart's admission policy).
func TestTenantDeleteNeedsConfirmation(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "keep"}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error { // the policy takes effect a moment after it's created
		if err := k8sClient.Delete(ctx, tenant); !apierrors.IsForbidden(err) {
			return fmt.Errorf("unconfirmed delete: want Forbidden, got %v", err)
		}
		return nil
	})
	if err := k8sClient.DeleteAllOf(ctx, &platformv1alpha1.Tenant{}); !apierrors.IsForbidden(err) {
		t.Fatalf("delete all Tenants: want Forbidden, got %v", err)
	}
	for _, wrong := range []string{"yes", "other"} {
		metav1.SetMetaDataAnnotation(&tenant.ObjectMeta, confirmDeleteAnno, wrong)
		if err := k8sClient.Update(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		if err := k8sClient.Delete(ctx, tenant); !apierrors.IsForbidden(err) {
			t.Fatalf("confirmed with %q: want Forbidden, got %v", wrong, err)
		}
	}
	metav1.SetMetaDataAnnotation(&tenant.ObjectMeta, confirmDeleteAnno, "keep")
	if err := k8sClient.Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Delete(ctx, tenant); err != nil {
		t.Fatalf("confirmed delete: %v", err)
	}
}

// A canary: the annotation gives one tenant's API server another image; removing it rolls back.
func TestAPIServerImageCanary(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "canary",
		Annotations: map[string]string{apiserverImageAnno: "tenant-apiserver:rc"}}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	image := func(want string) func() error {
		return func() error {
			sts := &appsv1.StatefulSet{}
			if err := apiReader.Get(ctx, client.ObjectKey{Namespace: "tenant-canary", Name: "apiserver"}, sts); err != nil {
				return err
			}
			if got := sts.Spec.Template.Spec.Containers[0].Image; got != want {
				return fmt.Errorf("image = %s, want %s", got, want)
			}
			return nil
		}
	}
	eventually(t, image("tenant-apiserver:rc"))
	patch := client.MergeFrom(tenant.DeepCopy())
	delete(tenant.Annotations, apiserverImageAnno)
	if err := k8sClient.Patch(ctx, tenant, patch); err != nil {
		t.Fatal(err)
	}
	eventually(t, image("tenant-apiserver:test"))
}

// The owner's limits decide which controllers run and with what (allocate), and the
// ResourceQuota on their pods: the budget plus room for a rolling update of the largest.
func TestControllerQuota(t *testing.T) {
	ctx := context.Background()
	acct := &accounts{Client: k8sClient, ns: "platform-system"}
	if err := acct.putUser(ctx, "github:quota", statusActive, platformv1alpha1.Limits{ControlPlanes: 1, Controllers: 2, CPU: "500m", Memory: "512Mi"}); err != nil {
		t.Fatal(err)
	}
	mem := func(name, m string) platformv1alpha1.ControllerSpec {
		return platformv1alpha1.ControllerSpec{Name: name, Image: "i", Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(m)}}}
	}
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "quota"}, Spec: platformv1alpha1.TenantSpec{
		Owners:      []string{"github:quota"},
		Controllers: []platformv1alpha1.ControllerSpec{mem("a", "100Mi"), mem("b", "412Mi"), mem("c", "1Mi")}}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	ns := "tenant-quota"
	eventually(t, func() error {
		q, dep := &corev1.ResourceQuota{}, &appsv1.Deployment{}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "controllers"}, q); err != nil {
			return err
		}
		h := q.Spec.Hard
		if got := fmt.Sprintf("pods=%s cpu=%s memory=%s", h.Pods(), h.Name(corev1.ResourceLimitsCPU, ""), h.Name(corev1.ResourceLimitsMemory, "")); got != "pods=3 cpu=750m memory=924Mi" {
			return fmt.Errorf("quota %s", got)
		}
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctrl-b"}, dep); err != nil {
			return err
		}
		if m := dep.Spec.Template.Spec.Containers[0].Resources.Limits.Memory(); m.String() != "412Mi" {
			return fmt.Errorf("ctrl-b memory limit = %s", m)
		}
		if pc := dep.Spec.Template.Spec.PriorityClassName; pc != controllerPriorityClass {
			return fmt.Errorf("priorityClassName = %q", pc)
		}
		return nil
	})
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctrl-c"}, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("ctrl-c beyond the account's 2 controllers: %v", err)
	}
}

// The resources view lists a type as `kubectl get` does: the API server's Table, without NAME
// (kept apart for the link) and without wide-only columns. Tenant's CRD has printer columns.
func TestKindTable(t *testing.T) {
	ctx := context.Background()
	if err := k8sClient.Create(ctx, &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "tabled"}}); err != nil {
		t.Fatal(err)
	}
	hc, err := rest.HTTPClientFor(restCfg)
	if err != nil {
		t.Fatal(err)
	}
	k := kindTable{Kind: "Tenant", Group: "platform.ctrlplane.run", Version: "v1alpha1", Resource: "tenants"}
	if err := k.load(ctx, hc, restCfg.Host); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(k.Columns, []string{"ID", "ENDPOINT", "AGE"}) {
		t.Errorf("columns = %v", k.Columns)
	}
	i := slices.IndexFunc(k.Rows, func(r kindRow) bool { return r.Name == "tabled" })
	if i < 0 || len(k.Rows[i].Cells) != len(k.Columns) {
		t.Fatalf("rows = %+v", k.Rows)
	}
	if age := k.Rows[i].Cells[2]; age == "" || age == "<none>" {
		t.Errorf("age = %q", age)
	}

	// User's printer columns leave out Age, which the API server then doesn't add: the site does.
	acct := &accounts{Client: k8sClient, ns: "platform-system"}
	if err := acct.putUser(ctx, "github:tabled", statusActive, platformv1alpha1.Limits{ControlPlanes: 1}); err != nil {
		t.Fatal(err)
	}
	u := kindTable{Kind: "User", Group: "platform.ctrlplane.run", Version: "v1alpha1", Resource: "users"}
	if err := u.load(ctx, hc, restCfg.Host); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(u.Columns, []string{"LOGIN", "STATUS", "CONTROL PLANES", "AGE"}) {
		t.Errorf("user columns = %v", u.Columns)
	}
	for _, r := range u.Rows {
		if len(r.Cells) != len(u.Columns) || r.Cells[len(r.Cells)-1] == "" {
			t.Errorf("user row %s: cells %v", r.Name, r.Cells)
		}
	}
}
