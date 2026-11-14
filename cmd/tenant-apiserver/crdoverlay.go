package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsapiserver "k8s.io/apiextensions-apiserver/pkg/apiserver"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	cacherstorage "k8s.io/apiserver/pkg/storage/cacher"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"
)

// Plugins: operators the platform runs once, on the host (Crossplane providers, ASO, ...). Their
// CRDs are not stored in each tenant's database: the platform mounts them as files
// (<dir>/<plugin>/*.yaml) and the API server serves them from memory as a read-only overlay under
// the tenant's own CRDs, for discovery, OpenAPI and RBAC like any CRD. The owner can't change or
// delete them, and they're the same across tenants and restarts. Their resources are the host's
// (pluginproxy.go), so only namespaced CRDs are served.

var crdResource = schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}

const labelPlugin = "platform.ctrlplane.run/plugin"

// loadPluginCRDs reads every namespaced CRD under dir, one subdirectory per plugin. Each comes back
// as the API server would store it once established, so the apiextensions controllers have nothing
// to write.
func loadPluginCRDs(dir string) (map[string]*apiextensions.CustomResourceDefinition, error) {
	crds := map[string]*apiextensions.CustomResourceDefinition{}
	now := metav1.NewTime(time.Now().Truncate(time.Second))
	decoder := apiextensionsapiserver.Codecs.UniversalDecoder()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
			return err
		}
		plugin := filepath.Base(filepath.Dir(p))
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		docs := utilyaml.NewYAMLReader(bufio.NewReader(f))
		for {
			doc, err := docs.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if strings.TrimSpace(string(doc)) == "" {
				continue
			}
			obj, _, err := decoder.Decode(doc, nil, nil)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			crd, ok := obj.(*apiextensions.CustomResourceDefinition)
			if !ok {
				return fmt.Errorf("%s: %s is not a CustomResourceDefinition", p, obj.GetObjectKind().GroupVersionKind().Kind)
			}
			if crd.Spec.Scope != apiextensions.NamespaceScoped { // e.g. a provider's cluster-wide config: the host's alone
				continue
			}
			if crds[crd.Name] != nil {
				return fmt.Errorf("%s: CRD %s is in two plugins", p, crd.Name)
			}
			establish(crd, plugin, now)
			crds[crd.Name] = crd
		}
	})
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return crds, err
}

func establish(crd *apiextensions.CustomResourceDefinition, plugin string, now metav1.Time) {
	if crd.Labels == nil {
		crd.Labels = map[string]string{}
	}
	crd.Labels[labelPlugin] = plugin
	// The CRD handler keys its serving state by UID; constant, so it's the same after a restart.
	crd.UID = types.UID(uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://ctrlplane.run/plugin-crd/"+crd.Name)).String())
	crd.ResourceVersion = "1" // never newer than the database's, so no client waits for it
	crd.Generation = 1
	crd.CreationTimestamp = now
	crd.Status.AcceptedNames = crd.Spec.Names
	crd.Status.StoredVersions = nil
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			crd.Status.StoredVersions = append(crd.Status.StoredVersions, v.Name)
		}
	}
	crd.Status.Conditions = []apiextensions.CustomResourceDefinitionCondition{
		{Type: apiextensions.NamesAccepted, Status: apiextensions.ConditionTrue, LastTransitionTime: now, Reason: "NoConflicts", Message: "no conflicts found"},
		{Type: apiextensions.Established, Status: apiextensions.ConditionTrue, LastTransitionTime: now, Reason: "InitialNamesAccepted", Message: "the initial names have been accepted"},
	}
	// The host converts (its objects, its operator's webhooks); this API server never reads them.
	crd.Spec.Conversion = &apiextensions.CustomResourceConversion{Strategy: apiextensions.NoneConverter}
}

// pluginCRDStorage makes the CRD store serve crds on top of the tenant's own: a RESTOptionsGetter
// that, for customresourcedefinitions only, puts crdOverlay between the database and the watch
// cache (otherwise upstream's StorageWithCacher).
func pluginCRDStorage(getter generic.RESTOptionsGetter, crds map[string]*apiextensions.CustomResourceDefinition) generic.RESTOptionsGetter {
	return overlayOptions{getter, crds}
}

type overlayOptions struct {
	generic.RESTOptionsGetter
	crds map[string]*apiextensions.CustomResourceDefinition
}

func (o overlayOptions) GetRESTOptions(resource schema.GroupResource, example runtime.Object) (generic.RESTOptions, error) {
	opts, err := o.RESTOptionsGetter.GetRESTOptions(resource, example)
	if err != nil || resource != crdResource {
		return opts, err
	}
	opts.Decorator = func(config *storagebackend.ConfigForResource, resourcePrefix string, keyFunc func(runtime.Object) (string, error),
		newFunc, newListFunc func() runtime.Object, getAttrs storage.AttrFunc, triggers storage.IndexerFuncs, indexers *cache.Indexers) (storage.Interface, factory.DestroyFunc, error) {
		s, destroy, err := generic.NewRawStorage(config, newFunc, newListFunc, resourcePrefix)
		if err != nil {
			return s, destroy, err
		}
		overlay := &crdOverlay{Interface: s, crds: o.crds}
		cacher, err := cacherstorage.NewCacherFromConfig(cacherstorage.Config{
			Storage: overlay, Versioner: storage.APIObjectVersioner{}, GroupResource: config.GroupResource,
			EventsHistoryWindow: config.EventsHistoryWindow, ResourcePrefix: resourcePrefix, KeyFunc: keyFunc,
			NewFunc: newFunc, NewListFunc: newListFunc, GetAttrsFunc: getAttrs, IndexerFuncs: triggers, Indexers: indexers, Codec: config.Codec,
		})
		if err != nil {
			return nil, func() {}, err
		}
		delegator := cacherstorage.NewCacheDelegator(cacher, overlay)
		var once sync.Once
		return delegator, func() { once.Do(func() { delegator.Stop(); cacher.Stop(); destroy() }) }, nil
	}
	return opts, nil
}

// crdOverlay is the tenant's CRD storage plus the plugin CRDs, which win on a name clash and
// take no writes. Reads of them answer the same whatever resource version is asked for, so
// the watch cache and the database agree.
type crdOverlay struct {
	storage.Interface
	crds map[string]*apiextensions.CustomResourceDefinition
}

// IsWatchListSemanticsUnSupported makes the watch cache fill itself with GetList + Watch
// (client-go's default watch-list would build the initial state inside etcd3's watcher,
// bypassing this overlay).
func (o *crdOverlay) IsWatchListSemanticsUnSupported() bool { return true }

func (o *crdOverlay) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
	if crd := o.crds[path.Base(key)]; crd != nil {
		out, ok := objPtr.(*apiextensions.CustomResourceDefinition)
		if !ok {
			return fmt.Errorf("plugin CRD %s: unexpected object type %T", crd.Name, objPtr)
		}
		crd.DeepCopyInto(out)
		return nil
	}
	return o.Interface.Get(ctx, key, opts, objPtr)
}

func (o *crdOverlay) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	if err := o.Interface.GetList(ctx, key, opts, listObj); err != nil {
		return err
	}
	list, ok := listObj.(*apiextensions.CustomResourceDefinitionList)
	if !ok {
		return nil
	}
	list.Items = slices.DeleteFunc(list.Items, func(c apiextensions.CustomResourceDefinition) bool { return o.crds[c.Name] != nil })
	if list.Continue != "" {
		return nil // shortcut: the overlay goes on the last page, which may exceed the limit; paginate it if a tenant ever lists thousands of CRDs
	}
	for _, crd := range o.crds {
		if !opts.Recursive && crd.Name != path.Base(key) {
			continue
		}
		if ok, err := opts.Predicate.Matches(crd); err != nil || !ok {
			continue
		}
		list.Items = append(list.Items, *crd.DeepCopy())
	}
	return nil
}

func (o *crdOverlay) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	if o.crds[path.Base(key)] != nil {
		return storage.NewKeyExistsError(key, 0)
	}
	return o.Interface.Create(ctx, key, obj, out, ttl)
}

func (o *crdOverlay) Delete(ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions,
	validateDeletion storage.ValidateObjectFunc, cachedExistingObject runtime.Object, opts storage.DeleteOptions) error {
	if err := o.readOnly(key); err != nil {
		return err
	}
	return o.Interface.Delete(ctx, key, out, preconditions, validateDeletion, cachedExistingObject, opts)
}

func (o *crdOverlay) GuaranteedUpdate(ctx context.Context, key string, destination runtime.Object, ignoreNotFound bool,
	preconditions *storage.Preconditions, tryUpdate storage.UpdateFunc, cachedExistingObject runtime.Object) error {
	if err := o.readOnly(key); err != nil {
		return err
	}
	return o.Interface.GuaranteedUpdate(ctx, key, destination, ignoreNotFound, preconditions, tryUpdate, cachedExistingObject)
}

// readOnly is a StatusError, which the registry passes through: the client gets a plain 403.
func (o *crdOverlay) readOnly(key string) error {
	if crd := o.crds[path.Base(key)]; crd != nil {
		return apierrors.NewForbidden(crdResource, crd.Name, fmt.Errorf("this CRD comes with plugin %s and is read-only; turn the plugin off instead", crd.Labels[labelPlugin]))
	}
	return nil
}
