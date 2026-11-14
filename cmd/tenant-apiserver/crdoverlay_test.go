package main

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
)

const vmCRD = `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: virtualmachines.proxmox.example.com
spec:
  group: proxmox.example.com
  scope: Namespaced
  names: {kind: VirtualMachine, plural: virtualmachines}
  conversion:
    strategy: Webhook
    webhook:
      conversionReviewVersions: [v1]
      clientConfig: {service: {namespace: proxmox-system, name: proxmox}}
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema: {openAPIV3Schema: {type: object, x-kubernetes-preserve-unknown-fields: true}}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: disks.proxmox.example.com
spec:
  group: proxmox.example.com
  scope: Namespaced
  names: {kind: Disk, plural: disks}
  versions:
  - name: v1
    served: true
    storage: true
    schema: {openAPIV3Schema: {type: object}}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clusterconfigs.proxmox.example.com
spec:
  group: proxmox.example.com
  scope: Cluster
  names: {kind: ClusterConfig, plural: clusterconfigs}
  versions:
  - name: v1
    served: true
    storage: true
    schema: {openAPIV3Schema: {type: object}}
`

// tenantCRDs is the tenant's own CRD storage: a list, plus one error per write.
type tenantCRDs struct {
	storage.Interface
	items  []apiextensions.CustomResourceDefinition
	cont   string
	writes int
}

func (s *tenantCRDs) Get(context.Context, string, storage.GetOptions, runtime.Object) error {
	return storage.NewKeyNotFoundError("", 0)
}

func (s *tenantCRDs) GetList(_ context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	l := listObj.(*apiextensions.CustomResourceDefinitionList)
	l.Items, l.Continue, l.ResourceVersion = nil, s.cont, "42"
	for _, c := range s.items {
		if opts.Recursive || c.Name == path.Base(key) {
			l.Items = append(l.Items, c)
		}
	}
	return nil
}
func (s *tenantCRDs) Create(context.Context, string, runtime.Object, runtime.Object, uint64) error {
	s.writes++
	return nil
}
func (s *tenantCRDs) Delete(context.Context, string, runtime.Object, *storage.Preconditions, storage.ValidateObjectFunc, runtime.Object, storage.DeleteOptions) error {
	s.writes++
	return nil
}
func (s *tenantCRDs) GuaranteedUpdate(context.Context, string, runtime.Object, bool, *storage.Preconditions, storage.UpdateFunc, runtime.Object) error {
	s.writes++
	return nil
}

func TestCRDOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "proxmox"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxmox", "crds.yaml"), []byte(vmCRD), 0o644); err != nil {
		t.Fatal(err)
	}
	crds, err := loadPluginCRDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	vm := crds["virtualmachines.proxmox.example.com"]
	if len(crds) != 2 || vm == nil { // not the cluster-scoped one
		t.Fatalf("loaded %v", crds)
	}
	if vm.Labels[labelPlugin] != "proxmox" || vm.UID == "" || vm.ResourceVersion != "1" || vm.Status.AcceptedNames.Plural != "virtualmachines" ||
		vm.Status.AcceptedNames.ListKind != "VirtualMachineList" || len(vm.Status.StoredVersions) != 1 || !apiextensions.IsCRDConditionTrue(vm, apiextensions.Established) ||
		!apiextensions.IsCRDConditionTrue(vm, apiextensions.NamesAccepted) {
		t.Errorf("not established as stored: %+v", vm)
	}
	if c := vm.Spec.Conversion; c.Strategy != apiextensions.NoneConverter || c.WebhookClientConfig != nil {
		t.Errorf("conversion %+v: the host converts", c)
	}
	again, _ := loadPluginCRDs(dir)
	if again["disks.proxmox.example.com"].UID != crds["disks.proxmox.example.com"].UID {
		t.Error("UID changes between loads")
	}
	if _, err := loadPluginCRDs(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing dir: %v", err)
	}

	tenant := &tenantCRDs{items: []apiextensions.CustomResourceDefinition{{ObjectMeta: metav1.ObjectMeta{Name: "own.example.com"}}, {ObjectMeta: metav1.ObjectMeta{Name: "disks.proxmox.example.com"}}}}
	o := &crdOverlay{Interface: tenant, crds: crds}
	ctx := context.Background()
	key := "/apiextensions.k8s.io/customresourcedefinitions/"

	list := &apiextensions.CustomResourceDefinitionList{}
	if err := o.GetList(ctx, key, storage.ListOptions{Recursive: true, Predicate: storage.Everything}, list); err != nil {
		t.Fatal(err)
	}
	if names := crdNames(list); len(names) != 3 || !names["own.example.com"] || !names["disks.proxmox.example.com"] || !names["virtualmachines.proxmox.example.com"] {
		t.Errorf("merged list %v", names)
	}
	for _, c := range list.Items { // the plugin's copy wins over the tenant's
		if c.Name == "disks.proxmox.example.com" && c.Labels[labelPlugin] != "proxmox" {
			t.Error("tenant's clashing CRD served")
		}
	}
	tenant.cont = "more"
	list = &apiextensions.CustomResourceDefinitionList{}
	_ = o.GetList(ctx, key, storage.ListOptions{Recursive: true, Predicate: storage.Everything}, list)
	if len(list.Items) != 1 {
		t.Errorf("overlay before the last page: %v", crdNames(list))
	}
	tenant.cont = ""
	list = &apiextensions.CustomResourceDefinitionList{}
	_ = o.GetList(ctx, key+"disks.proxmox.example.com", storage.ListOptions{Predicate: storage.Everything}, list)
	if n := crdNames(list); len(n) != 1 || !n["disks.proxmox.example.com"] {
		t.Errorf("single-key list %v", n)
	}

	got := &apiextensions.CustomResourceDefinition{}
	if err := o.Get(ctx, key+"virtualmachines.proxmox.example.com", storage.GetOptions{}, got); err != nil || got.UID != vm.UID {
		t.Errorf("get: %v %v", err, got.UID)
	}
	got.Labels["x"] = "y"
	if vm.Labels["x"] != "" {
		t.Error("Get returned the overlay's own object")
	}
	if err := o.Get(ctx, key+"own.example.com", storage.GetOptions{}, got); !storage.IsNotFound(err) {
		t.Errorf("tenant get: %v", err)
	}

	if err := o.Create(ctx, key+"disks.proxmox.example.com", got, got, 0); !storage.IsExist(err) {
		t.Errorf("create: %v", err)
	}
	if err := o.Delete(ctx, key+"disks.proxmox.example.com", got, nil, nil, nil, storage.DeleteOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("delete: %v", err)
	}
	if err := o.GuaranteedUpdate(ctx, key+"disks.proxmox.example.com", got, false, nil, nil, nil); !apierrors.IsForbidden(err) {
		t.Errorf("update: %v", err)
	}
	if tenant.writes != 0 {
		t.Error("writes reached the tenant's storage")
	}
	if err := o.Create(ctx, key+"new.example.com", got, got, 0); err != nil || tenant.writes != 1 {
		t.Errorf("tenant create: %v %d", err, tenant.writes)
	}
	if !o.IsWatchListSemanticsUnSupported() {
		t.Error("watch-list must be off, or the cache never lists")
	}
}

func crdNames(l *apiextensions.CustomResourceDefinitionList) map[string]bool {
	m := map[string]bool{}
	for _, c := range l.Items {
		m[c.Name] = true
	}
	return m
}
