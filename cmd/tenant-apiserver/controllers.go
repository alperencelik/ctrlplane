package main

import (
	"context"
	"sort"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	admissionv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/controller-manager/pkg/informerfactory"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/controller/garbagecollector"
	namespacecontroller "k8s.io/kubernetes/pkg/controller/namespace"
	serviceaccountcontroller "k8s.io/kubernetes/pkg/controller/serviceaccount"

	"github.com/alperencelik/ctrlplane/pkg/pki"
)

// runControllers runs the kube-controller-manager controllers a nodeless
// control plane still needs, wired the same way kube-controller-manager does
// (cmd/kube-controller-manager/app/{core,controllermanager}.go).
func runControllers(ctx context.Context, cfg *rest.Config) error {
	const resync = 12 * time.Hour
	const gcSyncPeriod = 30 * time.Second
	logger := klog.FromContext(ctx)

	cfg = rest.CopyConfig(cfg)
	cfg.QPS, cfg.Burst = 200, 400 // loopback; namespace deletion is chatty
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	metaClient, err := metadata.NewForConfig(cfg)
	if err != nil {
		return err
	}

	shared := informers.NewSharedInformerFactory(client, resync)
	metaInformers := metadatainformer.NewSharedInformerFactory(metaClient, resync)
	gcInformers := informerfactory.NewInformerFactory(shared, metaInformers)

	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(client.Discovery()))
	go wait.Until(mapper.Reset, gcSyncPeriod, ctx.Done())

	ns := namespacecontroller.NewNamespaceController(ctx, client, metaClient,
		client.Discovery().ServerPreferredNamespacedResources,
		shared.Core().V1().Namespaces(), 5*time.Minute, v1.FinalizerKubernetes)

	sa, err := serviceaccountcontroller.NewServiceAccountsController(logger,
		shared.Core().V1().ServiceAccounts(), shared.Core().V1().Namespaces(),
		client, serviceaccountcontroller.DefaultServiceAccountsControllerOptions())
	if err != nil {
		return err
	}

	informersStarted := make(chan struct{})
	gc, err := garbagecollector.NewGarbageCollector(ctx, client, metaClient, mapper,
		garbagecollector.DefaultIgnoredResources(), gcInformers, informersStarted)
	if err != nil {
		return err
	}

	go ns.Run(ctx, 10)
	go sa.Run(ctx, 1)
	go gc.Run(ctx, 20, gcSyncPeriod)
	// Picks up CRDs added later so their ownerReferences get collected too.
	go gc.Sync(ctx, client.Discovery(), gcSyncPeriod)

	gcInformers.Start(ctx.Done())
	close(informersStarted)
	return nil
}

// bootstrapTenantNamespace creates the tenant's namespace and lets the platform-run controllers
// (group pki.ControllerGroup, in their client certs) do anything inside that namespace, and
// nothing outside it. Other ServiceAccounts there (tokens owners make, e.g. for Grafana or CI)
// get only this tenant's metrics and logs, plus what owners grant them. Owners get the same as controllers, plus CRDs
// (cluster-scoped) and their controllers' status/logs; no kube-system, and no
// listing or creating namespaces. Retries until the API is ready.
//
// RBAC can't subtract, and a namespaced "*" also covers the Namespace object
// itself, so an admission policy lets only system:masters (loopback, platform)
// update/delete namespaces or the platform's tenant-controllers/tenant-owners RBAC.
func bootstrapTenantNamespace(ctx context.Context, cfg *rest.Config, ns string, owners []string) {
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "tenant namespace bootstrap")
		return
	}
	apply := metav1.ApplyOptions{FieldManager: "tenant-bootstrap", Force: true}
	_ = wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		if _, err := client.CoreV1().Namespaces().Apply(ctx, corev1ac.Namespace(ns), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().Roles(ns).Apply(ctx, rbacv1ac.Role("tenant-controllers", ns).
			WithRules(rbacv1ac.PolicyRule().WithAPIGroups("*").WithResources("*").WithVerbs("*")), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().RoleBindings(ns).Apply(ctx, rbacv1ac.RoleBinding("tenant-controllers", ns).
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("Role").WithName("tenant-controllers")).
			WithSubjects(rbacv1ac.Subject().WithKind("Group").WithAPIGroup("rbac.authorization.k8s.io").WithName(pki.ControllerGroup)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		protect := "tenant-protect"
		if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Apply(ctx, admissionv1ac.ValidatingAdmissionPolicy(protect).
			WithSpec(admissionv1ac.ValidatingAdmissionPolicySpec().
				WithFailurePolicy(admissionv1.Fail).
				WithMatchConstraints(admissionv1ac.MatchResources().WithResourceRules(
					admissionv1ac.NamedRuleWithOperations().WithOperations(admissionv1.Update, admissionv1.Delete).
						WithAPIGroups("", "rbac.authorization.k8s.io").WithAPIVersions("*").WithResources("namespaces", "namespaces/*", "roles", "rolebindings"))).
				// The object's own name, not request.name: a delete-collection admits each item with none.
				WithValidations(admissionv1ac.Validation().
					WithExpression(`request.userInfo.groups.exists(g, g == 'system:masters') || (request.resource.resource != 'namespaces' && !((request.operation == 'DELETE' ? oldObject : object).metadata.name in ['tenant-controllers', 'tenant-owners', 'tenant-custom-resources']))`).
					WithMessage("the tenant namespace and its tenant-controllers/tenant-owners RBAC are managed by the platform"))), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Apply(ctx, admissionv1ac.ValidatingAdmissionPolicyBinding(protect).
			WithSpec(admissionv1ac.ValidatingAdmissionPolicyBindingSpec().WithPolicyName(protect).WithValidationActions(admissionv1.Deny)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// Owners' webhooks (their controllers', see webhooks.go) may only intercept the tenant's own
		// API groups, like tenant-custom-resources: a webhook on RBAC or namespaces could rewrite
		// what the platform applies here. And they call Services (their controllers'), never URLs:
		// a URL would have this API server connect wherever its pod can reach.
		webhooks := "tenant-webhooks"
		if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Apply(ctx, admissionv1ac.ValidatingAdmissionPolicy(webhooks).
			WithSpec(admissionv1ac.ValidatingAdmissionPolicySpec().
				WithFailurePolicy(admissionv1.Fail).
				WithMatchConstraints(admissionv1ac.MatchResources().WithResourceRules(
					admissionv1ac.NamedRuleWithOperations().WithOperations(admissionv1.Create, admissionv1.Update).
						WithAPIGroups("admissionregistration.k8s.io").WithAPIVersions("*").WithResources("validatingwebhookconfigurations", "mutatingwebhookconfigurations"))).
				WithValidations(admissionv1ac.Validation().
					WithExpression(`request.userInfo.groups.exists(g, g == 'system:masters') || !has(object.webhooks) || object.webhooks.all(w, !has(w.rules) || w.rules.all(r, r.apiGroups.all(g, g != '' && g != '*' && !g.endsWith('k8s.io') && !g.endsWith('kubernetes.io'))))`).
					WithMessage("webhooks may only match your own API groups (not '*', core or *.k8s.io)"),
					admissionv1ac.Validation().
						WithExpression(`request.userInfo.groups.exists(g, g == 'system:masters') || !has(object.webhooks) || object.webhooks.all(w, !has(w.clientConfig.url))`).
						WithMessage("webhooks call your controllers' Services (clientConfig.service, e.g. ctrl-<controller>-webhook), not URLs"))), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Apply(ctx, admissionv1ac.ValidatingAdmissionPolicyBinding(webhooks).
			WithSpec(admissionv1ac.ValidatingAdmissionPolicyBindingSpec().WithPolicyName(webhooks).WithValidationActions(admissionv1.Deny)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// CRD conversion webhooks, likewise: Services, not URLs.
		conversion := "tenant-crd-conversion"
		if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Apply(ctx, admissionv1ac.ValidatingAdmissionPolicy(conversion).
			WithSpec(admissionv1ac.ValidatingAdmissionPolicySpec().
				WithFailurePolicy(admissionv1.Fail).
				WithMatchConstraints(admissionv1ac.MatchResources().WithResourceRules(
					admissionv1ac.NamedRuleWithOperations().WithOperations(admissionv1.Create, admissionv1.Update).
						WithAPIGroups("apiextensions.k8s.io").WithAPIVersions("*").WithResources("customresourcedefinitions"))).
				WithValidations(admissionv1ac.Validation().
					WithExpression(`request.userInfo.groups.exists(g, g == 'system:masters') || !has(object.spec.conversion) || !has(object.spec.conversion.webhook) || !has(object.spec.conversion.webhook.clientConfig) || !has(object.spec.conversion.webhook.clientConfig.url)`).
					WithMessage("conversion webhooks call your controllers' Services (clientConfig.service), not URLs"))), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Apply(ctx, admissionv1ac.ValidatingAdmissionPolicyBinding(conversion).
			WithSpec(admissionv1ac.ValidatingAdmissionPolicyBindingSpec().WithPolicyName(conversion).WithValidationActions(admissionv1.Deny)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// Re-applied on every start, so removing an owner from --tenant-owners revokes it.
		if _, err := client.RbacV1().ClusterRoles().Apply(ctx, rbacv1ac.ClusterRole("tenant-owner").WithRules(
			rbacv1ac.PolicyRule().WithAPIGroups("apiextensions.k8s.io").WithResources("customresourcedefinitions").WithVerbs("*"),
			rbacv1ac.PolicyRule().WithAPIGroups("admissionregistration.k8s.io").
				WithResources("validatingwebhookconfigurations", "mutatingwebhookconfigurations").WithVerbs("*"),
			rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("namespaces").WithResourceNames(ns).WithVerbs("get", "watch"),
			rbacv1ac.PolicyRule().WithNonResourceURLs("/platform/controllers", "/platform/controllers/*").WithVerbs("get"),
			rbacv1ac.PolicyRule().WithNonResourceURLs("/platform/metrics/*", "/platform/logs/*").WithVerbs("get", "post")), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		clusterBinding := rbacv1ac.ClusterRoleBinding("tenant-owner").
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("ClusterRole").WithName("tenant-owner"))
		nsBinding := rbacv1ac.RoleBinding("tenant-owners", ns).
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("Role").WithName("tenant-controllers"))
		for _, o := range owners {
			clusterBinding.WithSubjects(rbacv1ac.Subject().WithKind("User").WithAPIGroup("rbac.authorization.k8s.io").WithName(o))
			nsBinding.WithSubjects(rbacv1ac.Subject().WithKind("User").WithAPIGroup("rbac.authorization.k8s.io").WithName(o))
		}
		if _, err := client.RbacV1().ClusterRoleBindings().Apply(ctx, clusterBinding, apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().RoleBindings(ns).Apply(ctx, nsBinding, apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// ServiceAccounts in ns (e.g. a token for your own Grafana) may query this tenant's metrics and logs.
		if _, err := client.RbacV1().ClusterRoles().Apply(ctx, rbacv1ac.ClusterRole("tenant-metrics-reader").WithRules(
			rbacv1ac.PolicyRule().WithNonResourceURLs("/platform/metrics/*", "/platform/logs/*").WithVerbs("get", "post")), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().ClusterRoleBindings().Apply(ctx, rbacv1ac.ClusterRoleBinding("tenant-metrics-reader").
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("ClusterRole").WithName("tenant-metrics-reader")).
			WithSubjects(rbacv1ac.Subject().WithKind("Group").WithAPIGroup("rbac.authorization.k8s.io").WithName("system:serviceaccounts:"+ns)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// HTTPS metrics endpoints (controller-runtime's authn/authz filter) are scraped with
		// tokens of this service account (metrics-proxy sidecar): GET /metrics, and like every
		// other service account in ns, this tenant's metrics and logs. Nothing else.
		if _, err := client.CoreV1().ServiceAccounts(ns).Apply(ctx, corev1ac.ServiceAccount(metricsScraperSA, ns), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().ClusterRoles().Apply(ctx, rbacv1ac.ClusterRole("tenant-metrics-scrape").WithRules(
			rbacv1ac.PolicyRule().WithNonResourceURLs("/metrics").WithVerbs("get")), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().ClusterRoleBindings().Apply(ctx, rbacv1ac.ClusterRoleBinding("tenant-metrics-scrape").
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("ClusterRole").WithName("tenant-metrics-scrape")).
			WithSubjects(rbacv1ac.Subject().WithKind("ServiceAccount").WithName(metricsScraperSA).WithNamespace(ns)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// ...and the controllers serving them check those tokens (kubebuilder's metrics-auth-role):
		// review-only APIs, they grant nothing.
		if _, err := client.RbacV1().ClusterRoles().Apply(ctx, rbacv1ac.ClusterRole("tenant-metrics-auth").WithRules(
			rbacv1ac.PolicyRule().WithAPIGroups("authentication.k8s.io").WithResources("tokenreviews").WithVerbs("create"),
			rbacv1ac.PolicyRule().WithAPIGroups("authorization.k8s.io").WithResources("subjectaccessreviews").WithVerbs("create")), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().ClusterRoleBindings().Apply(ctx, rbacv1ac.ClusterRoleBinding("tenant-metrics-auth").
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("ClusterRole").WithName("tenant-metrics-auth")).
			WithSubjects(rbacv1ac.Subject().WithKind("Group").WithAPIGroup("rbac.authorization.k8s.io").WithName(pki.ControllerGroup)), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// Events about cluster-scoped objects (e.g. a kubemox VirtualMachine) always go to
		// "default": controllers may record them there, owners may read them; nothing else.
		if _, err := client.CoreV1().Namespaces().Apply(ctx, corev1ac.Namespace(metav1.NamespaceDefault), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		if _, err := client.RbacV1().Roles(metav1.NamespaceDefault).Apply(ctx, rbacv1ac.Role("tenant-cluster-events", metav1.NamespaceDefault).WithRules(
			rbacv1ac.PolicyRule().WithAPIGroups("", "events.k8s.io").WithResources("events").WithVerbs("create", "update", "patch", "get", "list", "watch")), apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		eventsBinding := rbacv1ac.RoleBinding("tenant-cluster-events", metav1.NamespaceDefault).
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("Role").WithName("tenant-cluster-events")).
			WithSubjects(rbacv1ac.Subject().WithKind("Group").WithAPIGroup("rbac.authorization.k8s.io").WithName(pki.ControllerGroup))
		for _, o := range owners {
			eventsBinding.WithSubjects(rbacv1ac.Subject().WithKind("User").WithAPIGroup("rbac.authorization.k8s.io").WithName(o))
		}
		if _, err := client.RbacV1().RoleBindings(metav1.NamespaceDefault).Apply(ctx, eventsBinding, apply); err != nil {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		// Tenants created before owners were scoped: drop their cluster-admin binding.
		if err := client.RbacV1().ClusterRoleBindings().Delete(ctx, "tenant-owners", metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			klog.V(2).InfoS("tenant namespace bootstrap retry", "err", err)
			return false, nil
		}
		klog.InfoS("tenant namespace bootstrapped", "namespace", ns, "owners", owners)
		return true, nil
	})
}

// syncCustomResourceRole keeps ClusterRole tenant-custom-resources in step with the
// tenant's CRDs: full access to each CRD's own resources (anywhere, since many are
// cluster-scoped) and read access to CRDs, bound to the owners and to the platform-run
// controllers (pki.ControllerGroup). Operators like kubemox then just work, without cluster-admin.
//
// Rules name each CRD's exact resources, and *.k8s.io / *.kubernetes.io groups are
// skipped, so a CRD can never widen access to built-in APIs.
func syncCustomResourceRole(ctx context.Context, cfg *rest.Config, ns string, owners []string) {
	const name = "tenant-custom-resources"
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "custom resource role")
		return
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "custom resource role")
		return
	}
	apply := metav1.ApplyOptions{FieldManager: "tenant-bootstrap", Force: true}
	binding := rbacv1ac.ClusterRoleBinding(name).
		WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("ClusterRole").WithName(name)).
		WithSubjects(rbacv1ac.Subject().WithKind("Group").WithAPIGroup("rbac.authorization.k8s.io").WithName(pki.ControllerGroup))
	for _, o := range owners {
		binding.WithSubjects(rbacv1ac.Subject().WithKind("User").WithAPIGroup("rbac.authorization.k8s.io").WithName(o))
	}
	_ = wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := client.RbacV1().ClusterRoleBindings().Apply(ctx, binding, apply)
		return err == nil, nil
	})

	informer := dynamicinformer.NewDynamicSharedInformerFactory(dc, 12*time.Hour).
		ForResource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	enqueue := func(any) { queue.Add(name) }
	_, _ = informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: enqueue, UpdateFunc: func(_, o any) { enqueue(o) }, DeleteFunc: enqueue,
	})
	go informer.Informer().Run(ctx.Done())
	go func() { <-ctx.Done(); queue.ShutDown() }()
	// A tenant with no CRDs gets no events, and the binding above would point at a missing role.
	if cache.WaitForCacheSync(ctx.Done(), informer.Informer().HasSynced) {
		queue.Add(name)
	}
	for {
		key, shutdown := queue.Get()
		if shutdown {
			return
		}
		role := rbacv1ac.ClusterRole(name).WithRules(rbacv1ac.PolicyRule().
			WithAPIGroups("apiextensions.k8s.io").WithResources("customresourcedefinitions").WithVerbs("get", "list", "watch"))
		objs, _ := informer.Lister().List(labels.Everything()) // cache read; never errors
		sort.Slice(objs, func(i, j int) bool {
			return objs[i].(*unstructured.Unstructured).GetName() < objs[j].(*unstructured.Unstructured).GetName()
		})
		for _, o := range objs {
			crd := o.(*unstructured.Unstructured).Object
			group, _, _ := unstructured.NestedString(crd, "spec", "group")
			plural, _, _ := unstructured.NestedString(crd, "spec", "names", "plural")
			if group == "" || plural == "" || strings.HasSuffix(group, "k8s.io") || strings.HasSuffix(group, "kubernetes.io") {
				continue
			}
			role.WithRules(rbacv1ac.PolicyRule().WithAPIGroups(group).
				WithResources(plural, plural+"/status", plural+"/finalizers", plural+"/scale").WithVerbs("*"))
		}
		if _, err := client.RbacV1().ClusterRoles().Apply(ctx, role, apply); err != nil {
			klog.V(2).InfoS("custom resource role retry", "err", err)
			queue.AddRateLimited(key)
		} else {
			queue.Forget(key)
		}
		queue.Done(key)
	}
}
