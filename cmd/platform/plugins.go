package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// Plugins: operators the hosting runs once, on the host cluster (a Crossplane provider, ASO, ...),
// for every tenant that turns them on (spec.plugins). A tenant's objects of a plugin's types live
// in the host namespace plugins-<tenant>, where the operator reconciles them: the tenant API
// server serves the types (cmd/tenant-apiserver/crdoverlay.go) and forwards their requests there
// (pluginproxy.go) with its own ServiceAccount, which this file allows those resources in that
// namespace and nothing else. The catalog is a directory (PLUGINS_DIR, from the PLUGINS_IMAGE
// image, which the hosting maintains along with the operators):
//
//	<dir>/<plugin>/plugin.yaml   name, description, docs (below)
//	<dir>/<plugin>/crds.yaml     its CRDs, as installed on the host; tenants get the namespaced ones
//	<dir>/<plugin>/example.yaml  optional: how to use it, for the catalog page; <namespace> is filled in
//
// The tenant API server gets the enabled plugins' crds.yaml through an init container from the
// same image.
type plugin struct {
	APIVersion string `json:"apiVersion"` // plugins.ctrlplane.run/v1alpha1
	Kind       string `json:"kind"`       // Plugin
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Description string `json:"description"`
		Docs        string `json:"docs,omitempty"`  // upstream API reference
		Guide       string `json:"guide,omitempty"` // how to use it on ctrlplane (docs-site)
	} `json:"spec"`
}

func (p *plugin) Name() string { return p.Metadata.Name }

var pluginName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,30}[a-z0-9])?$`)

const (
	pluginCRDsPath = "/plugin-crds"                  // in the tenant API server pod
	labelPlugin    = "platform.ctrlplane.run/plugin" // on the CRDs the API server serves for a plugin
	// labelPluginSecret: a tenant's Secret with it set to "true" is copied to its plugins
	// namespace, for the operators (credentials, e.g. a ProviderConfig's secretRef).
	labelPluginSecret = "plugins.ctrlplane.run/copy"
	labelPluginsOf    = "platform.ctrlplane.run/plugins-of" // on plugins-<tenant> and what the platform puts there
	// pluginObjects caps each plugin resource per tenant (a ResourceQuota): one tenant's thousands
	// would slow the shared operator for everyone.
	// shortcut: one number for every resource and tenant; make it an account limit when plans differ
	pluginObjects = 100
)

// pluginsNamespace is the host namespace of a tenant's plugin resources. Not tenant-<name>: the
// operators read Secrets in it by name, and that one holds the tenant's PKI and kubeconfigs.
func pluginsNamespace(tenant string) string { return "plugins-" + tenant }

func loadPlugin(dir, name string) (*plugin, error) {
	if !pluginName.MatchString(name) {
		return nil, fmt.Errorf("plugin %q: no such plugin", name)
	}
	b, err := os.ReadFile(filepath.Join(dir, name, "plugin.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("plugin %q: no such plugin", name)
	}
	if err != nil {
		return nil, err
	}
	p := &plugin{}
	if err := yaml.UnmarshalStrict(b, p); err != nil {
		return nil, fmt.Errorf("plugin %q: %w", name, err)
	}
	if p.Metadata.Name != name {
		return nil, fmt.Errorf("plugin %q: plugin.yaml names it %q", name, p.Metadata.Name)
	}
	return p, nil
}

// listPlugins is the catalog, by name.
func listPlugins(dir string) ([]plugin, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []plugin
	for _, e := range entries {
		if p, err := loadPlugin(dir, e.Name()); err == nil {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// pluginCRD is what the platform needs to know of a plugin's namespaced CRDs (crds.yaml): for the
// tenant's RBAC and quota on the host, and to refuse turning a plugin on over a tenant's own CRD
// in its groups, and off while its resources exist.
type pluginCRD struct {
	Name     string
	Kind     string
	Group    string
	Version  string // the storage version
	Resource string // plural
}

func pluginCRDs(dir, name string) ([]pluginCRD, error) {
	f, err := os.Open(filepath.Join(dir, name, "crds.yaml"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []pluginCRD
	docs := utilyaml.NewYAMLReader(bufio.NewReader(f))
	for {
		doc, err := docs.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		var crd struct {
			Metadata metav1.ObjectMeta `json:"metadata"`
			Spec     struct {
				Group    string `json:"group"`
				Scope    string `json:"scope"`
				Names    struct{ Plural, Kind string }
				Versions []struct {
					Name    string
					Storage bool
				}
			}
		}
		if err := yaml.Unmarshal(doc, &crd); err != nil {
			return nil, err
		}
		if crd.Metadata.Name == "" || crd.Spec.Scope != "Namespaced" { // tenants don't get cluster-scoped ones (crdoverlay.go)
			continue
		}
		c := pluginCRD{Name: crd.Metadata.Name, Kind: crd.Spec.Names.Kind, Group: crd.Spec.Group, Resource: crd.Spec.Names.Plural}
		for _, v := range crd.Spec.Versions {
			if v.Storage {
				c.Version = v.Name
			}
		}
		out = append(out, c)
	}
}

// inCatalog keeps the plugins the catalog still has. One a release dropped stays in spec.plugins
// but is no longer served; failing on it would stop the whole tenant's reconcile.
func inCatalog(dir string, plugins []string) []string {
	return slices.DeleteFunc(slices.Clone(plugins), func(p string) bool {
		_, err := os.Stat(filepath.Join(dir, p, "crds.yaml"))
		return err != nil
	})
}

// applyPluginsNamespace sets up plugins-<tenant> for the enabled plugins: the namespace, the
// tenant API server's Role there (only their resources; status read-only, it's the operator's),
// and the quota. With none enabled it deletes the namespace (turning the last one off already
// checked it's empty, togglePlugin). Plugins not in the catalog get no rules, but still keep the
// namespace: deleting it would delete their objects, and the operator the cloud resources.
func (r *reconciler) applyPluginsNamespace(ctx context.Context, tenant, ns string, plugins []string, owner *metav1ac.OwnerReferenceApplyConfiguration) error {
	pns := pluginsNamespace(tenant)
	if len(plugins) == 0 { // from the cache: most tenants never had one, and this runs on every reconcile
		n := &corev1.Namespace{}
		if err := r.Get(ctx, client.ObjectKey{Name: pns}, n); err != nil || n.DeletionTimestamp != nil {
			return client.IgnoreNotFound(err)
		}
		return client.IgnoreNotFound(r.Delete(ctx, n))
	}
	labels := map[string]string{labelPluginsOf: tenant}
	role := rbacv1ac.Role("plugin-resources", pns).WithLabels(labels)
	hard := corev1.ResourceList{corev1.ResourceSecrets: resource.MustParse("50")}
	for _, name := range plugins {
		crds, err := pluginCRDs(r.pluginsDir, name)
		if errors.Is(err, os.ErrNotExist) {
			continue // dropped from the catalog (inCatalog); its objects stay here, out of the tenant's reach
		}
		if err != nil {
			return fmt.Errorf("plugin %s: %w", name, err)
		}
		for _, c := range crds {
			role.WithRules(
				rbacv1ac.PolicyRule().WithAPIGroups(c.Group).WithResources(c.Resource).WithVerbs("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"),
				rbacv1ac.PolicyRule().WithAPIGroups(c.Group).WithResources(c.Resource+"/status").WithVerbs("get"))
			hard[corev1.ResourceName("count/"+c.Resource+"."+c.Group)] = *resource.NewQuantity(pluginObjects, resource.DecimalSI)
		}
	}
	// Pod Security "restricted" too: nothing runs there, and nothing should.
	nsLabels := map[string]string{labelPluginsOf: tenant, "pod-security.kubernetes.io/enforce": "restricted"}
	for _, obj := range []runtime.ApplyConfiguration{
		corev1ac.Namespace(pns).WithOwnerReferences(owner).WithLabels(nsLabels),
		role,
		rbacv1ac.RoleBinding("plugin-resources", pns).WithLabels(labels).
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup(rbacv1.GroupName).WithKind("Role").WithName("plugin-resources")).
			WithSubjects(rbacv1ac.Subject().WithKind("ServiceAccount").WithName("apiserver").WithNamespace(ns)),
		corev1ac.ResourceQuota("plugin-resources", pns).WithLabels(labels).WithSpec(corev1ac.ResourceQuotaSpec().WithHard(hard)),
	} {
		if err := r.Apply(ctx, obj, fieldOwner, client.ForceOwnership); err != nil {
			return err
		}
	}
	return nil
}

// syncPluginSecrets copies the tenant's Secrets labeled labelPluginSecret=true (in its namespace
// in the tenant API server) to plugins-<tenant>, and deletes copies whose original is gone.
// shortcut: one way, by polling (Reconcile); Secrets an operator writes there (connection details)
// don't come back to the tenant yet. Sync them back when a plugin needs it.
func (r *reconciler) syncPluginSecrets(ctx context.Context, tenant, tenantNS string) error {
	cfg, err := tenantAdmin(ctx, r.Client, r.platformNS, tenant)
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	src, err := cs.CoreV1().Secrets(tenantNS).List(ctx, metav1.ListOptions{LabelSelector: labelPluginSecret + "=true"})
	if err != nil {
		return err
	}
	pns, keep := pluginsNamespace(tenant), map[string]bool{}
	for _, s := range src.Items {
		keep[s.Name] = true
		dst := corev1ac.Secret(s.Name, pns).WithLabels(map[string]string{labelPluginsOf: tenant}).WithType(s.Type).WithData(s.Data)
		if err := r.Apply(ctx, dst, fieldOwner, client.ForceOwnership); err != nil {
			return fmt.Errorf("secret %s: %w", s.Name, err)
		}
	}
	copies := &corev1.SecretList{}
	if err := r.List(ctx, copies, client.InNamespace(pns), client.MatchingLabels{labelPluginsOf: tenant}); err != nil {
		return err
	}
	for i := range copies.Items {
		if !keep[copies.Items[i].Name] {
			if err := client.IgnoreNotFound(r.Delete(ctx, &copies.Items[i])); err != nil {
				return err
			}
		}
	}
	return nil
}

// tenantAdmin reaches a tenant's API server as system:masters, through its in-cluster Service
// (NetworkPolicy platform-to-apiserver), for the plugins' Secrets and resources.
func tenantAdmin(ctx context.Context, r client.Reader, platformNS, tenant string) (*rest.Config, error) {
	s := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: platformNS, Name: tenant + "-tenant-pki"}, s); err != nil || len(s.Data["admin.kubeconfig"]) == 0 {
		return nil, errors.New("tenant is still provisioning")
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(s.Data["admin.kubeconfig"])
	if err != nil {
		return nil, err
	}
	cfg.Host = fmt.Sprintf("https://apiserver.tenant-%s.svc:%d", tenant, apiserverPort)
	cfg.Timeout = 15 * time.Second
	return cfg, nil
}

// pluginCRDsInUse says which of a plugin's CRDs have objects, e.g. "3 buckets.s3.aws.upbound.io".
func pluginCRDsInUse(ctx context.Context, cfg *rest.Config, crds []pluginCRD) ([]string, error) {
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	var used []string
	for _, crd := range crds {
		l, err := dc.Resource(schema.GroupVersionResource{Group: crd.Group, Version: crd.Version, Resource: crd.Resource}).List(ctx, metav1.ListOptions{Limit: 100})
		if apierrors.IsNotFound(err) {
			continue // not served (plugin off already)
		}
		if err != nil {
			return nil, err
		}
		if n := len(l.Items); n > 0 {
			used = append(used, fmt.Sprintf("%d %s", n, crd.Name))
		}
	}
	return used, nil
}
