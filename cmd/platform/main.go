// platform runs on the host cluster and turns each Tenant into:
//   - namespace tenant-<name> with a default-deny-from-outside NetworkPolicy
//   - a tenant-apiserver StatefulSet + Service, backed by a PVC
//   - one Deployment per spec.controllers[], talking to the tenant API server as
//     ServiceAccount <tenant>/<controller>, whose RBAC is limited to namespace <tenant>
//     (created and bound by tenant-apiserver --tenant-namespace)
package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	networkingv1ac "k8s.io/client-go/applyconfigurations/networking/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
	"github.com/alperencelik/ctrlplane/pkg/pki"
)

const (
	fieldOwner      = client.FieldOwner("platform")
	labelTenant     = "platform.ctrlplane.run/tenant"
	labelController = "platform.ctrlplane.run/controller"
	identityAnno    = "platform.ctrlplane.run/identity"
	certAnno        = "platform.ctrlplane.run/cert" // on pod templates: certHash of the pod's cert
	webhookCertAnno = "platform.ctrlplane.run/webhook-cert"
	labelWebhook    = "platform.ctrlplane.run/webhook" // on a controller's webhook Service and cert: the controller
	// controller-runtime's default: its webhook server reads tls.crt and tls.key from here.
	webhookCertDir = "/tmp/k8s-webhook-server/serving-certs"
	// On the metrics scraper's pods: the one platform pod that may reach tenant pods.
	labelMetricsScraper = "platform.ctrlplane.run/metrics-scraper"
	labelPullSecret     = "platform.ctrlplane.run/pull-secret" // on copies of the platform's pull secrets
	// Deleting a Tenant needs this annotation, set to its name (config/policy/tenant-delete-policy.yaml).
	confirmDeleteAnno = "platform.ctrlplane.run/confirm-delete"
	// Canary: this tenant's API server runs this image instead of TENANT_APISERVER_IMAGE. Admins
	// only: owners change Tenants through the site, which never sets annotations.
	apiserverImageAnno = "platform.ctrlplane.run/apiserver-image"
	apiserverPort      = 6443
	nonRootUID         = 65532
	kubeconfigPath     = "/var/run/tenant/kubeconfig"
	// In-cluster namespace file: controller-runtime leader election and client-go read it.
	saDir = "/var/run/secrets/kubernetes.io/serviceaccount"
)

// metricsProxyPort is where the metrics-proxy sidecar serves an HTTPS endpoint as plain HTTP;
// its limits count toward the controllers' ResourceQuota.
const (
	metricsProxyPort   = 9099
	metricsProxyCPU    = "100m"
	metricsProxyMemory = "256Mi"
)

// controllerPriorityClass is on every controller pod, so the tenant's
// ResourceQuota can count just those.
const controllerPriorityClass = "ctrlplane-tenant-controller"

// metricsHTTPS: the controller serves metrics behind controller-runtime's authn/authz filter; a
// metrics-proxy sidecar scrapes it with a tenant token and serves it to the platform as plain HTTP.
func metricsHTTPS(c platformv1alpha1.ControllerSpec) bool {
	return c.Metrics != nil && c.Metrics.Port != 0 && c.Metrics.Scheme == "https"
}

// metricsAnnotations tell the platform's scraper where a controller serves metrics:
// default :8080/metrics (controller-runtime's), port 0 = off.
func metricsAnnotations(c platformv1alpha1.ControllerSpec) map[string]string {
	port, path := int32(8080), "/metrics"
	if c.Metrics != nil {
		port, path = c.Metrics.Port, cmp.Or(c.Metrics.Path, path)
	}
	if port == 0 {
		return nil
	}
	if metricsHTTPS(c) {
		port, path = metricsProxyPort, "/metrics"
	}
	return map[string]string{"platform.ctrlplane.run/metrics-port": fmt.Sprint(port), "platform.ctrlplane.run/metrics-path": path}
}

// scheme: built-in types plus Tenant and User.
var scheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = platformv1alpha1.AddToScheme(s)
	return s
}()

// The platform's ClusterRole rules (config/rbac/role.yaml), generated by `make manifests`. The website
// creates, edits and deletes Tenants and Users on behalf of signed-in owners.
// +kubebuilder:rbac:groups=platform.ctrlplane.run,resources=tenants;users,verbs=get;list;watch;create;update;delete
// patch: the site sets a Tenant's delete confirmation annotation (a merge patch: no conflict with status writes).
// +kubebuilder:rbac:groups=platform.ctrlplane.run,resources=tenants,verbs=patch
// +kubebuilder:rbac:groups=platform.ctrlplane.run,resources=tenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=namespaces;secrets;services;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=resourcequotas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=tlsroutes,verbs=get;list;watch;create;update;patch;delete
// pods, pods/log: held so the platform may grant them (RBAC escalation check) to tenant API servers;
// watch: the log shipper (logship.go) follows controller pods.
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list
// Node addresses, kept out of reach of tenant code (tenant-egress).
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list

type reconciler struct {
	client.Client
	apiReader      client.Reader // uncached: the host API's endpoints, without watching every EndpointSlice
	platformNS     string
	apiserverImage string
	acct           *accounts
	// Registry credentials (Secrets in platformNS) for the platform's own images, copied into each
	// tenant namespace. Only pods whose images the platform chooses (API server, tunnel) use them:
	// on a controller pod the kubelet would also use them for the tenant's image.
	pullSecrets []string
	// Requests/limits of the tenant API server and the tunnel's main container; empty = none.
	apiserverResources, tunnelResources corev1.ResourceRequirements
	// PVC of new tenant API servers; existing ones keep theirs (see apiserverClaim).
	storageSize  resource.Quantity
	storageClass string   // empty = the cluster's default StorageClass
	backups      *backups // nil = no backups, and no restoreFrom (backup.go)
	metricsURL   string   // VictoriaMetrics, queried by tenant API servers; empty = no /platform/metrics
	logsURL      string   // VictoriaLogs, likewise for /platform/logs
	runtimeClass string
	// Public endpoints https://<tenantID>.<domain>[:port] via a Gateway API TLSRoute
	// (TLS passthrough). Disabled when domain is empty.
	domain         string
	endpointPort   string
	gateway        string // <namespace>/<name> of the shared Gateway
	gatewayProxyNS string // where the gateway's proxy pods run (allowed in by NetworkPolicy)
	// Tunnel into the tenant's network: chisel connectors dial https://<tenantID>.<tunnelDomain>.
	tunnelDomain   string
	chiselImage    string
	tailscaleImage string
	// OIDC (Dex): tenant API servers accept its ID tokens; empty issuer = client certs only.
	oidcIssuer string
	oidcCA     []byte // PEM; empty = system roots
	workers    int    // tenants reconciled at once (0 = 1)
}

// usernameExpr maps Dex ID tokens to tenant usernames: github:<login> (local users: local:<email>).
// Tokens must be requested with scope federated:id. The web app mirrors it in userOf.
const usernameExpr = `claims.federated_claims.connector_id + ':' + (has(claims.preferred_username) ? claims.preferred_username : claims.email)`

// oidcClients are the Dex clients whose ID tokens tenant API servers accept.
var oidcClients = []string{"ctrlplane-web", "ctrlplane-cli"}

func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	t := &platformv1alpha1.Tenant{}
	if err := r.Get(ctx, req.NamespacedName, t); err != nil || t.DeletionTimestamp != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err) // children go away via ownerReferences
	}
	spec := *t.Spec.DeepCopy() // with the owners' accounts applied, not written back
	lim := r.applyAccounts(ctx, t.GetName(), &spec)

	ns := "tenant-" + t.GetName() // host namespace
	tenantNS := t.GetName()       // namespace inside the tenant API server
	owner := metav1ac.OwnerReference().
		WithAPIVersion(platformv1alpha1.GroupVersion.String()).WithKind("Tenant").
		WithName(t.GetName()).WithUID(t.GetUID()).
		WithController(true).WithBlockOwnerDeletion(true)
	tenantLabels := map[string]string{labelTenant: t.GetName()}
	server := fmt.Sprintf("https://apiserver.%s.svc:%d", ns, apiserverPort) // in-cluster, for controllers
	id := tenantID(t.GetUID())
	if t.Spec.RestoreFrom != nil {
		// A restored tenant keeps its ID, so its endpoint, CA and existing kubeconfigs are unchanged.
		id = t.Spec.RestoreFrom.TenantID
		if other, err := r.tenantWithID(ctx, id, t.Name); err != nil || other != "" {
			return ctrl.Result{}, cmp.Or(err, fmt.Errorf("spec.restoreFrom: Tenant %s still has ID %s; delete it first", other, id))
		}
	}
	publicHost, endpoint := "", server
	if r.domain != "" {
		publicHost = id + "." + r.domain
		endpoint = "https://" + publicHost
		if r.endpointPort != "443" {
			endpoint += ":" + r.endpointPort
		}
	}

	// Pod Security "restricted": the platform's pods already comply; enforcing it means nothing
	// else can run less confined in a namespace that runs tenant code.
	nsLabels := maps.Clone(tenantLabels)
	nsLabels["pod-security.kubernetes.io/enforce"] = "restricted"
	nsLabels["pod-security.kubernetes.io/enforce-version"] = "latest"
	if err := r.Apply(ctx, corev1ac.Namespace(ns).WithLabels(nsLabels).WithOwnerReferences(owner), fieldOwner, client.ForceOwnership); err != nil {
		return ctrl.Result{}, err
	}
	restoreSnap := "" // spec.restoreFrom's snapshot: the PKI and the database both come from it
	if t.Spec.RestoreFrom != nil {
		var err error
		if restoreSnap, err = r.restoreSnapshot(ctx, t); err != nil {
			return ctrl.Result{}, err
		}
	}
	ca, err := r.ensurePKI(ctx, t, ns, endpoint, publicHost, tenantNS, restoreSnap, owner)
	if err != nil {
		return ctrl.Result{}, err
	}
	authn, err := r.authnConfig()
	if err != nil {
		return ctrl.Result{}, err
	}
	egress, apiserverEgress, err := r.egressPolicies(ctx, ns, owner)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.copyPullSecrets(ctx, ns, owner); err != nil {
		return ctrl.Result{}, err
	}
	claim, err := r.apiserverClaim(ctx, ns)
	if err != nil {
		return ctrl.Result{}, err
	}
	var requeue time.Duration // to refresh the restore URL
	if restoreSnap != "" {    // before the StatefulSet: its init container needs the Secret
		if requeue, err = r.reconcileRestore(ctx, t, ns, restoreSnap, owner); err != nil {
			return ctrl.Result{}, err
		}
	}
	for _, obj := range []runtime.ApplyConfiguration{
		egress, apiserverEgress,
		// Only pods of this tenant may connect to pods of this tenant.
		networkingv1ac.NetworkPolicy("tenant-isolation", ns).WithOwnerReferences(owner).WithSpec(
			networkingv1ac.NetworkPolicySpec().
				WithPodSelector(metav1ac.LabelSelector()).
				WithPolicyTypes(networkingv1.PolicyTypeIngress).
				WithIngress(networkingv1ac.NetworkPolicyIngressRule().WithFrom(
					networkingv1ac.NetworkPolicyPeer().WithPodSelector(metav1ac.LabelSelector()),
					// The platform's metrics scraper (VictoriaMetrics, labelled by the Helm chart).
					networkingv1ac.NetworkPolicyPeer().
						WithNamespaceSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"kubernetes.io/metadata.name": r.platformNS})).
						WithPodSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{labelMetricsScraper: "true"}))))),
		// The apiserver gets its serving cert and SA key, never ca.key.
		corev1ac.Secret("apiserver-pki", ns).WithOwnerReferences(owner).WithData(map[string][]byte{
			"ca.crt": ca["ca.crt"], "apiserver.crt": ca["apiserver.crt"], "apiserver.key": ca["apiserver.key"], "sa.key": ca["sa.key"],
			"public.crt": ca["public.crt"], "public.key": ca["public.key"],
			"authn.yaml": authn, "audit.yaml": auditPolicy,
		}),
		// The platform reaches the API server in-cluster for backups (snapshotDB), on its port only.
		networkingv1ac.NetworkPolicy("platform-to-apiserver", ns).WithOwnerReferences(owner).WithSpec(networkingv1ac.NetworkPolicySpec().
			WithPodSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"app": "apiserver"})).
			WithPolicyTypes(networkingv1.PolicyTypeIngress).
			WithIngress(networkingv1ac.NetworkPolicyIngressRule().
				WithFrom(networkingv1ac.NetworkPolicyPeer().
					WithNamespaceSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"kubernetes.io/metadata.name": r.platformNS})).
					WithPodSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"app": "platform"}))).
				WithPorts(networkingv1ac.NetworkPolicyPort().WithPort(intstr.FromInt32(apiserverPort))))),
		// The tenant API server's host identity: read-only pods + logs of this namespace,
		// so tenant owners can see their controllers via /platform/controllers.
		corev1ac.ServiceAccount("apiserver", ns).WithOwnerReferences(owner),
		rbacv1ac.Role("apiserver-controller-logs", ns).WithOwnerReferences(owner).WithRules(
			rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("pods").WithVerbs("get", "list"),
			rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("pods/log").WithVerbs("get")),
		rbacv1ac.RoleBinding("apiserver-controller-logs", ns).WithOwnerReferences(owner).
			WithRoleRef(rbacv1ac.RoleRef().WithAPIGroup("rbac.authorization.k8s.io").WithKind("Role").WithName("apiserver-controller-logs")).
			WithSubjects(rbacv1ac.Subject().WithKind("ServiceAccount").WithName("apiserver").WithNamespace(ns)),
		controllerQuota(ns, lim, spec.Controllers, owner),
		r.apiserverService(ns, owner),
		r.apiserverStatefulSet(ns, tenantNS, publicHost, cmp.Or(t.Annotations[apiserverImageAnno], r.apiserverImage), spec.Owners, claim, restoreSnap != "", owner),
	} {
		if err := r.Apply(ctx, obj, fieldOwner, client.ForceOwnership); err != nil {
			return ctrl.Result{}, err
		}
	}
	if publicHost != "" {
		if err := r.applyPassthrough(ctx, ns, "apiserver", publicHost, apiserverPort, owner); err != nil {
			return ctrl.Result{}, err
		}
	}
	tunnelURL, err := r.reconcileTunnel(ctx, t.GetName(), ns, id, spec.Tunnel, ca, owner)
	if err != nil {
		return ctrl.Result{}, err
	}
	// status.backup is the backupper's (backup.go).
	if err := r.setStatus(ctx, t, platformv1alpha1.TenantStatus{ID: id, Endpoint: endpoint, Tunnel: tunnelURL,
		Backup: t.Status.Backup, RestoredSnapshot: restoreSnap}); err != nil {
		return ctrl.Result{}, err
	}

	want, webhooks := map[string]bool{}, map[string]bool{}
	for _, c := range spec.Controllers {
		want[c.Name] = true
		cert, err := r.ensureControllerKubeconfig(ctx, ns, server, tenantNS, c.Name, ca, owner)
		if err != nil {
			return ctrl.Result{}, err
		}
		webhookCert := ""
		if c.Webhook != nil {
			webhooks[c.Name] = true
			if webhookCert, err = r.ensureWebhook(ctx, ns, tenantNS, c, ca, owner); err != nil {
				return ctrl.Result{}, err
			}
		}
		if err := r.Apply(ctx, r.controllerDeployment(ns, tenantNS, c, spec.Tunnel, cert, webhookCert, owner), fieldOwner, client.ForceOwnership); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: requeue}, r.prune(ctx, ns, want, webhooks)
}

// ensurePKI returns the tenant PKI, generating the CA once. It lives in the platform
// namespace so nothing running in the tenant namespace can read ca.key. If the
// public host or endpoint changes, the serving cert / admin kubeconfig are re-issued
// with the same CA, so existing client credentials stay valid.
func (r *reconciler) ensurePKI(ctx context.Context, t *platformv1alpha1.Tenant, ns, endpoint, publicHost, tenantNS, restoreSnap string, owner *metav1ac.OwnerReferenceApplyConfiguration) (map[string][]byte, error) {
	// The in-cluster names (they name the tenant) are on the default serving cert; the public
	// endpoint has a cert of its own (public.crt, served for its name by SNI), so a client that
	// knows only the endpoint learns nothing more from the cert.
	hosts := []string{"apiserver", "apiserver." + ns, "apiserver." + ns + ".svc", "apiserver." + ns + ".svc.cluster.local", "localhost", "127.0.0.1"}
	s := &corev1.Secret{}
	key := client.ObjectKey{Namespace: r.platformNS, Name: t.GetName() + "-tenant-pki"}
	err := r.Get(ctx, key, s)
	switch {
	case err == nil && len(s.OwnerReferences) > 0 && !slices.ContainsFunc(s.OwnerReferences, func(o metav1.OwnerReference) bool { return o.UID == t.GetUID() }):
		// A deleted tenant's of the same name, not yet garbage-collected: never reuse its CA.
		return nil, fmt.Errorf("the PKI of a deleted tenant named %s is still being removed; retrying", t.GetName())
	case err == nil:
	case !apierrors.IsNotFound(err):
		return nil, err
	case restoreSnap != "": // the backed-up CA and keys; the fixes below re-issue for this tenant's hosts
		if s.Data, err = r.restoredPKI(ctx, t, restoreSnap); err != nil {
			return nil, err
		}
	default:
		if s.Data, err = pki.Generate(hosts, endpoint, tenantNS); err != nil {
			return nil, err
		}
	}
	d, changed := s.Data, false
	// Re-issued from the same CA when hosts change or they near expiry; the API server reloads
	// its serving cert, and the platform reads the admin kubeconfig on each use (backups).
	if !pki.Current(d["apiserver.crt"], hosts...) || publicHost != "" && pki.Current(d["apiserver.crt"], publicHost) {
		if d["apiserver.crt"], d["apiserver.key"], err = pki.ServingCert(d["ca.crt"], d["ca.key"], hosts); err != nil {
			return nil, err
		}
		changed = true
	}
	if publicHost != "" && !pki.Current(d["public.crt"], publicHost) {
		if d["public.crt"], d["public.key"], err = pki.ServingCert(d["ca.crt"], d["ca.key"], []string{publicHost}); err != nil {
			return nil, err
		}
		changed = true
	}
	if !pki.Current(d["admin.crt"]) {
		if d["admin.crt"], d["admin.key"], err = pki.ClientCert(d["ca.crt"], d["ca.key"], "admin", "system:masters"); err != nil {
			return nil, err
		}
		changed = true
	}
	kc, err := pki.Kubeconfig(endpoint, tenantNS, d["ca.crt"], d["admin.crt"], d["admin.key"])
	if err != nil {
		return nil, err
	}
	if string(kc) != string(d["admin.kubeconfig"]) {
		d["admin.kubeconfig"], changed = kc, true
	}
	if s.UID == "" { // new
		s.ObjectMeta = metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Labels: map[string]string{labelTenant: t.GetName()},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: *owner.APIVersion, Kind: *owner.Kind, Name: *owner.Name, UID: *owner.UID}}}
		return d, r.Create(ctx, s)
	}
	if changed {
		return d, r.Update(ctx, s)
	}
	return d, nil
}

// applyPassthrough routes <host> to Service <name>:<port> (pods app=<name>) through the
// shared Gateway (TLS passthrough: TLS terminates at the tenant's own pod).
func (r *reconciler) applyPassthrough(ctx context.Context, ns, name, host string, port int32, owner *metav1ac.OwnerReferenceApplyConfiguration) error {
	gwNS, gwName, _ := strings.Cut(r.gateway, "/")
	ownerRef := map[string]any{"apiVersion": *owner.APIVersion, "kind": *owner.Kind, "name": *owner.Name, "uid": string(*owner.UID), "controller": true, "blockOwnerDeletion": true}
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "TLSRoute",
		"metadata":   map[string]any{"name": name, "namespace": ns, "ownerReferences": []any{ownerRef}},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": gwName, "namespace": gwNS}},
			"hostnames":  []any{host},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": name, "port": int64(port)}}}},
		},
	}}
	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(route), fieldOwner, client.ForceOwnership); err != nil {
		return err
	}
	// Let only the gateway's proxy pods reach only this port.
	return r.Apply(ctx, networkingv1ac.NetworkPolicy("gateway-to-"+name, ns).WithOwnerReferences(owner).WithSpec(
		networkingv1ac.NetworkPolicySpec().
			WithPodSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"app": name})).
			WithPolicyTypes(networkingv1.PolicyTypeIngress).
			WithIngress(networkingv1ac.NetworkPolicyIngressRule().
				WithFrom(networkingv1ac.NetworkPolicyPeer().WithNamespaceSelector(
					metav1ac.LabelSelector().WithMatchLabels(map[string]string{"kubernetes.io/metadata.name": r.gatewayProxyNS}))).
				WithPorts(networkingv1ac.NetworkPolicyPort().WithPort(intstr.FromInt32(port))))), fieldOwner, client.ForceOwnership)
}

// authnConfig is the tenant API server's structured authentication config: anonymous requests
// only for the health checks (the kubelet's probes; not /version), and Dex ID tokens.
func (r *reconciler) authnConfig() ([]byte, error) {
	var anonymous []any
	for _, p := range []string{"/healthz", "/livez", "/readyz"} {
		anonymous = append(anonymous, map[string]any{"path": p})
	}
	cfg := map[string]any{
		"apiVersion": "apiserver.config.k8s.io/v1",
		"kind":       "AuthenticationConfiguration",
		"anonymous":  map[string]any{"enabled": true, "conditions": anonymous},
	}
	if r.oidcIssuer != "" {
		issuer := map[string]any{"url": r.oidcIssuer, "audiences": oidcClients, "audienceMatchPolicy": "MatchAny"}
		if len(r.oidcCA) > 0 {
			issuer["certificateAuthority"] = string(r.oidcCA)
		}
		cfg["jwt"] = []any{map[string]any{
			"issuer":        issuer,
			"claimMappings": map[string]any{"username": map[string]any{"expression": usernameExpr}},
			// Required by the API server whenever the username may come from claims.email.
			"claimValidationRules": []any{map[string]any{
				"expression": "claims.email_verified == true", "message": "email must be verified"}},
		}}
	}
	return yaml.Marshal(cfg)
}

// auditPolicy: who did what in a tenant API server (metadata only: no object bodies, so no
// Secret data), written as JSON lines to the API server's stdout (its logs go to stderr). Not
// logged: the in-process controllers (loopback) and health checks.
var auditPolicy = []byte(`apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: None
    users: [system:apiserver]
  - level: None
    nonResourceURLs: [/healthz*, /livez*, /readyz*]
  - level: Metadata
`)

// setStatus merge-patches .status if it differs.
func (r *reconciler) setStatus(ctx context.Context, t *platformv1alpha1.Tenant, status platformv1alpha1.TenantStatus) error {
	if t.Status == status {
		return nil
	}
	patch := client.MergeFrom(t.DeepCopy())
	t.Status = status
	return r.Status().Patch(ctx, t, patch)
}

// tenantWithID names another Tenant (than self) whose ID is id, if any.
func (r *reconciler) tenantWithID(ctx context.Context, id, self string) (string, error) {
	list := &platformv1alpha1.TenantList{}
	if err := r.List(ctx, list); err != nil {
		return "", err
	}
	for _, o := range list.Items {
		if o.Name != self && o.Status.ID == id {
			return o.Name, nil
		}
	}
	return "", nil
}

// tenantID is a stable, DNS-safe ID derived from the Tenant's UID (used in public hostnames,
// so tenant names never leak into DNS and renames can't break endpoints).
func tenantID(uid types.UID) string {
	sum := sha256.Sum256([]byte(uid))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))[:10]
}

// ensureControllerKubeconfig mints a client cert that RBAC in the tenant API server
// treats as ServiceAccount <tenantNS>/<controller>. Re-minted only if that identity changes.
// ensureControllerKubeconfig keeps the controller's client-cert kubeconfig, re-issued when its
// identity changes or the cert nears expiry. It returns a hash of the cert for the pod template:
// a new cert restarts the controller, which may not reload its kubeconfig by itself.
func (r *reconciler) ensureControllerKubeconfig(ctx context.Context, ns, server, tenantNS, controller string, ca map[string][]byte, owner *metav1ac.OwnerReferenceApplyConfiguration) (string, error) {
	identity := "system:serviceaccount:" + tenantNS + ":" + controller
	// The annotation records the groups too: certs from before ControllerGroup are re-issued.
	identityAndGroups := identity + " " + pki.ControllerGroup
	existing := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: kubeconfigSecret(controller)}, existing)
	if crt := pki.KubeconfigCert(existing.Data["kubeconfig"]); err == nil && existing.Annotations[identityAnno] == identityAndGroups && pki.Current(crt) {
		return certHash(crt), nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return "", err
	}
	crt, key, err := pki.ClientCert(ca["ca.crt"], ca["ca.key"], identity, pki.ControllerGroup, "system:serviceaccounts", "system:serviceaccounts:"+tenantNS)
	if err != nil {
		return "", err
	}
	kc, err := pki.Kubeconfig(server, tenantNS, ca["ca.crt"], crt, key)
	if err != nil {
		return "", err
	}
	return certHash(crt), r.Apply(ctx, corev1ac.Secret(kubeconfigSecret(controller), ns).
		WithLabels(map[string]string{labelController: controller}).
		WithAnnotations(map[string]string{identityAnno: identityAndGroups}).
		WithOwnerReferences(owner).
		WithData(map[string][]byte{"kubeconfig": kc, "namespace": []byte(tenantNS)}), fieldOwner, client.ForceOwnership)
}

// ensureWebhook gives a controller's webhooks a Service and a serving cert from the tenant CA. The
// cert is for <svc>.<tenantNS>.svc, the name the tenant API server checks for a service reference
// (tenant-apiserver resolves it to this namespace), and for the host name <svc>.<ns>.svc. It returns
// a hash of the cert for the pod template, like ensureControllerKubeconfig.
func (r *reconciler) ensureWebhook(ctx context.Context, ns, tenantNS string, c platformv1alpha1.ControllerSpec, ca map[string][]byte, owner *metav1ac.OwnerReferenceApplyConfiguration) (string, error) {
	name := webhookName(c.Name)
	labels := map[string]string{labelWebhook: c.Name}
	// Port 443, as webhook configurations default to; the tenant-isolation policy already lets
	// the API server pod in.
	if err := r.Apply(ctx, corev1ac.Service(name, ns).WithLabels(labels).WithOwnerReferences(owner).WithSpec(corev1ac.ServiceSpec().
		WithSelector(map[string]string{labelController: c.Name}).
		WithPorts(corev1ac.ServicePort().WithName("https").WithPort(443).WithTargetPort(intstr.FromInt32(cmp.Or(c.Webhook.Port, 9443))))),
		fieldOwner, client.ForceOwnership); err != nil {
		return "", err
	}
	hosts := []string{name + "." + tenantNS + ".svc", name + "." + ns + ".svc"}
	s := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, s)
	if crt := s.Data[corev1.TLSCertKey]; err == nil && pki.Current(crt, hosts...) {
		return certHash(crt), nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return "", err
	}
	crt, key, err := pki.ServingCert(ca["ca.crt"], ca["ca.key"], hosts)
	if err != nil {
		return "", err
	}
	return certHash(crt), r.Apply(ctx, corev1ac.Secret(name, ns).WithLabels(labels).WithOwnerReferences(owner).
		WithType(corev1.SecretTypeTLS).WithData(map[string][]byte{corev1.TLSCertKey: crt, corev1.TLSPrivateKeyKey: key}),
		fieldOwner, client.ForceOwnership)
}

// prune deletes controllers (and their kubeconfigs) that were removed from spec, and the webhook
// Service and cert of controllers without webhooks.
func (r *reconciler) prune(ctx context.Context, ns string, want, webhooks map[string]bool) error {
	for _, list := range []client.ObjectList{&corev1.ServiceList{}, &corev1.SecretList{}} {
		if err := r.List(ctx, list, client.InNamespace(ns), client.HasLabels{labelWebhook}); err != nil {
			return err
		}
		if err := meta.EachListItem(list, func(o runtime.Object) error {
			if obj := o.(client.Object); !webhooks[obj.GetLabels()[labelWebhook]] {
				return client.IgnoreNotFound(r.Delete(ctx, obj))
			}
			return nil
		}); err != nil {
			return err
		}
	}
	deps := &appsv1.DeploymentList{}
	if err := r.List(ctx, deps, client.InNamespace(ns), client.HasLabels{labelController}); err != nil {
		return err
	}
	for i := range deps.Items {
		name := deps.Items[i].Labels[labelController]
		if want[name] {
			continue
		}
		if err := client.IgnoreNotFound(r.Delete(ctx, &deps.Items[i])); err != nil {
			return err
		}
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: kubeconfigSecret(name)}}
		if err := client.IgnoreNotFound(r.Delete(ctx, s)); err != nil {
			return err
		}
	}
	return nil
}

func (r *reconciler) apiserverService(ns string, owner *metav1ac.OwnerReferenceApplyConfiguration) *corev1ac.ServiceApplyConfiguration {
	return corev1ac.Service("apiserver", ns).WithOwnerReferences(owner).WithSpec(corev1ac.ServiceSpec().
		WithSelector(map[string]string{"app": "apiserver"}).
		WithPorts(corev1ac.ServicePort().WithName("https").WithPort(apiserverPort).WithTargetPort(intstr.FromInt32(apiserverPort))))
}

// apiserverClaim is the spec of the tenant API server's PVC template: the configured size and class
// for a new StatefulSet, the existing one's otherwise (the template can't change once created).
// ponytail: a bigger storageSize reaches new tenants only; grow existing PVCs directly (with a
// StorageClass that allows expansion).
func (r *reconciler) apiserverClaim(ctx context.Context, ns string) (*corev1ac.PersistentVolumeClaimSpecApplyConfiguration, error) {
	size, class := r.storageSize, r.storageClass
	sts := &appsv1.StatefulSet{}
	switch err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: "apiserver"}, sts); {
	case err == nil:
		for _, t := range sts.Spec.VolumeClaimTemplates {
			if t.Name == "data" {
				size, class = t.Spec.Resources.Requests[corev1.ResourceStorage], ptr.Deref(t.Spec.StorageClassName, "")
			}
		}
	case !apierrors.IsNotFound(err):
		return nil, err
	}
	spec := corev1ac.PersistentVolumeClaimSpec().WithAccessModes(corev1.ReadWriteOnce).
		WithResources(corev1ac.VolumeResourceRequirements().WithRequests(corev1.ResourceList{corev1.ResourceStorage: size}))
	if class != "" {
		spec.WithStorageClassName(class)
	}
	return spec, nil
}

// resources converts requests/limits to their apply configuration; nil when both are empty.
func resources(res corev1.ResourceRequirements) *corev1ac.ResourceRequirementsApplyConfiguration {
	if len(res.Requests) == 0 && len(res.Limits) == 0 {
		return nil
	}
	// Copies: Apply decodes the server's answer into the apply configuration, and res may be
	// the reconciler's own (shared by concurrent reconciles).
	ac := corev1ac.ResourceRequirements()
	if len(res.Requests) > 0 {
		ac.WithRequests(maps.Clone(res.Requests))
	}
	if len(res.Limits) > 0 {
		ac.WithLimits(maps.Clone(res.Limits))
	}
	return ac
}

func (r *reconciler) apiserverStatefulSet(ns, tenantNS, publicHost, image string, owners []string, claim *corev1ac.PersistentVolumeClaimSpecApplyConfiguration, restore bool, owner *metav1ac.OwnerReferenceApplyConfiguration) *appsv1ac.StatefulSetApplyConfiguration {
	labels := map[string]string{"app": "apiserver"}
	pvc := &corev1ac.PersistentVolumeClaimApplyConfiguration{}
	pvc.WithName("data").WithSpec(claim)

	args := []string{fmt.Sprintf("--secure-port=%d", apiserverPort), "--tenant-namespace=" + tenantNS, "--host-namespace=" + ns,
		// One tenant's request floods queue in its own API server (defaults: 400 and 200).
		"--max-requests-inflight=100", "--max-mutating-requests-inflight=25",
		"--tenant-owners=" + strings.Join(owners, ","),
		"--authentication-config=/data/pki/authn.yaml",
		"--audit-policy-file=/data/pki/audit.yaml", "--audit-log-path=-"}
	if publicHost != "" {
		args = append(args, "--tls-sni-cert-key=/data/pki/public.crt,/data/pki/public.key:"+publicHost)
	}
	if r.metricsURL != "" {
		args = append(args, "--metrics-url="+r.metricsURL)
	}
	if r.logsURL != "" {
		args = append(args, "--logs-url="+r.logsURL)
	}
	pod := r.withPullSecrets(r.hardenedPod()).
		WithContainers(corev1ac.Container().WithName("apiserver").WithImage(image).
			WithCommand("/tenant-apiserver").
			WithArgs(args...).
			WithWorkingDir("/data").
			WithPorts(corev1ac.ContainerPort().WithName("https").WithContainerPort(apiserverPort)).
			WithResources(resources(r.apiserverResources)).
			WithReadinessProbe(corev1ac.Probe().WithHTTPGet(corev1ac.HTTPGetAction().
				WithPath("/readyz").WithPort(intstr.FromInt32(apiserverPort)).WithScheme(corev1.URISchemeHTTPS))).
			WithVolumeMounts(
				corev1ac.VolumeMount().WithName("data").WithMountPath("/data"),
				corev1ac.VolumeMount().WithName("pki").WithMountPath("/data/pki").WithReadOnly(true)).
			WithSecurityContext(hardenedContainer())).
		WithVolumes(corev1ac.Volume().WithName("pki").WithSecret(corev1ac.SecretVolumeSource().WithSecretName("apiserver-pki")))
	pod.SecurityContext.WithFSGroup(nonRootUID) // PVC must be writable by the nonroot user
	if restore {                                // fills an empty volume from the backup (backup.go); a no-op once the database exists
		pod.WithInitContainers(corev1ac.Container().WithName("restore").WithImage(image).
			WithCommand("/tenant-apiserver").WithArgs("restore").WithWorkingDir("/data").
			// Optional: the Secret is deleted once the API server is ready, and a later restart
			// finds the database.
			WithEnvFrom(corev1ac.EnvFromSource().WithSecretRef(corev1ac.SecretEnvSource().WithName(restoreSecret).WithOptional(true))).
			WithVolumeMounts(corev1ac.VolumeMount().WithName("data").WithMountPath("/data")).
			WithResources(sidecarResources()).
			WithSecurityContext(hardenedContainer()))
	}
	pod.WithServiceAccountName("apiserver").WithAutomountServiceAccountToken(true)

	return appsv1ac.StatefulSet("apiserver", ns).WithOwnerReferences(owner).WithSpec(appsv1ac.StatefulSetSpec().
		WithReplicas(1).WithServiceName("apiserver").
		WithSelector(metav1ac.LabelSelector().WithMatchLabels(labels)).
		WithTemplate(corev1ac.PodTemplateSpec().WithLabels(labels).WithSpec(pod)).
		WithVolumeClaimTemplates(pvc))
}

func (r *reconciler) controllerDeployment(ns, tenantNS string, c platformv1alpha1.ControllerSpec, tunnel *platformv1alpha1.TunnelSpec, cert, webhookCert string, owner *metav1ac.OwnerReferenceApplyConfiguration) *appsv1ac.DeploymentApplyConfiguration {
	labels := map[string]string{labelController: c.Name}
	container := corev1ac.Container().WithName("controller").WithImage(c.Image).WithArgs(c.Args...).
		WithVolumeMounts(
			corev1ac.VolumeMount().WithName("tenant-kubeconfig").WithMountPath("/var/run/tenant").WithReadOnly(true),
			corev1ac.VolumeMount().WithName("tenant-namespace").WithMountPath(saDir).WithReadOnly(true),
			corev1ac.VolumeMount().WithName("tmp").WithMountPath("/tmp")).
		// The image is the tenant's: its files stay as built, it writes only to /tmp, and what it
		// writes is capped, so it can't fill the node's disk for everyone.
		WithSecurityContext(hardenedContainer().WithReadOnlyRootFilesystem(true))
	// controller-runtime and client-go pick KUBECONFIG over in-cluster config;
	// WATCH_NAMESPACE/POD_NAMESPACE point operators at the only namespace they may use;
	// HOME is for clients that only read ~/.kube/config (the kubeconfig is there too).
	platformEnv := [][2]string{{"KUBECONFIG", kubeconfigPath}, {"WATCH_NAMESPACE", tenantNS}, {"POD_NAMESPACE", tenantNS}, {"HOME", "/var/run/tenant"}}
	if tunnel != nil {
		// Everything but in-cluster Services (the tenant API server, forwards) goes through the
		// tunnel (socks5: Go resolves names at the far end, so the tenant's own DNS works).
		proxy := fmt.Sprintf("socks5://tunnel.%s.svc:%d", ns, socksPort)
		noProxy := []string{ns + ".svc", ns + ".svc.cluster.local"}
		for _, f := range tunnel.Forwards {
			noProxy = append(noProxy, f.Name)
		}
		platformEnv = append(platformEnv, [2]string{"HTTPS_PROXY", proxy}, [2]string{"HTTP_PROXY", proxy},
			[2]string{"NO_PROXY", strings.Join(noProxy, ",")})
	}
	reserved := map[string]bool{}
	for _, e := range platformEnv {
		reserved[e[0]] = true
	}
	for _, e := range c.Env {
		if !reserved[e.Name] {
			container.WithEnv(corev1ac.EnvVar().WithName(e.Name).WithValue(e.Value))
		}
	}
	for _, e := range platformEnv {
		container.WithEnv(corev1ac.EnvVar().WithName(e[0]).WithValue(e[1]))
	}
	res := resources(c.Resources)
	if res == nil {
		res = corev1ac.ResourceRequirements()
	}
	limits := corev1.ResourceList{corev1.ResourceEphemeralStorage: controllerScratch}
	if res.Limits != nil {
		maps.Copy(limits, *res.Limits) // WithLimits replaces the map: keep its CPU and memory
	}
	container.WithResources(res.WithLimits(limits))
	container.LivenessProbe, container.ReadinessProbe, container.StartupProbe = probe(c.LivenessProbe), probe(c.ReadinessProbe), probe(c.StartupProbe)
	annotations := map[string]string{certAnno: cert}
	if c.Webhook != nil {
		container.WithVolumeMounts(corev1ac.VolumeMount().WithName("webhook-cert").WithMountPath(webhookCertDir).WithReadOnly(true))
		annotations[webhookCertAnno] = webhookCert
	}

	pod := r.hardenedPod().WithPriorityClassName(controllerPriorityClass).WithContainers(container).
		WithVolumes(
			corev1ac.Volume().WithName("tmp").WithEmptyDir(corev1ac.EmptyDirVolumeSource().WithSizeLimit(controllerScratch)),
			corev1ac.Volume().WithName("tenant-kubeconfig").WithSecret(corev1ac.SecretVolumeSource().
				WithSecretName(kubeconfigSecret(c.Name)).WithItems(
				corev1ac.KeyToPath().WithKey("kubeconfig").WithPath("kubeconfig"),
				// For clients that only look at ~/.kube/config (HOME is /var/run/tenant).
				corev1ac.KeyToPath().WithKey("kubeconfig").WithPath(".kube/config"))),
			corev1ac.Volume().WithName("tenant-namespace").WithSecret(corev1ac.SecretVolumeSource().
				WithSecretName(kubeconfigSecret(c.Name)).WithItems(corev1ac.KeyToPath().WithKey("namespace").WithPath("namespace"))))
	// Only the tenant's own registry-* credentials, never the platform's pull secrets.
	for _, s := range c.ImagePullSecrets {
		pod.WithImagePullSecrets(corev1ac.LocalObjectReference().WithName(registrySecret(s)))
	}
	if c.Webhook != nil {
		pod.WithVolumes(corev1ac.Volume().WithName("webhook-cert").WithSecret(corev1ac.SecretVolumeSource().WithSecretName(webhookName(c.Name))))
	}

	return appsv1ac.Deployment("ctrl-"+c.Name, ns).WithLabels(labels).WithOwnerReferences(owner).WithSpec(appsv1ac.DeploymentSpec().
		WithReplicas(1).
		WithSelector(metav1ac.LabelSelector().WithMatchLabels(labels)).
		WithTemplate(corev1ac.PodTemplateSpec().WithLabels(labels).WithAnnotations(metricsAnnotations(c)).
			WithAnnotations(annotations).WithSpec(r.withMetricsProxy(pod, c, tenantNS))))
}

// hardenedPod: no host-cluster credentials, no host service env, non-root, sandboxed if configured.
func (r *reconciler) hardenedPod() *corev1ac.PodSpecApplyConfiguration {
	p := corev1ac.PodSpec().
		WithAutomountServiceAccountToken(false).
		WithEnableServiceLinks(false).
		WithSecurityContext(corev1ac.PodSecurityContext().
			WithRunAsNonRoot(true).WithRunAsUser(nonRootUID).WithRunAsGroup(nonRootUID).
			WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileTypeRuntimeDefault)))
	if r.runtimeClass != "" {
		p.WithRuntimeClassName(r.runtimeClass)
	}
	return p
}

func hardenedContainer() *corev1ac.SecurityContextApplyConfiguration {
	return corev1ac.SecurityContext().
		WithAllowPrivilegeEscalation(false).
		WithCapabilities(corev1ac.Capabilities().WithDrop("ALL"))
}

// withMetricsProxy adds the metrics-proxy sidecar for HTTPS metrics endpoints. It shares the
// controller's tenant kubeconfig to request tokens for the tenant's metrics scraper account.
// Its pod runs the tenant's image too, so it gets no pull secrets (see reconciler.pullSecrets):
// the tenant-apiserver image must be pullable without them (or already on the node).
func (r *reconciler) withMetricsProxy(pod *corev1ac.PodSpecApplyConfiguration, c platformv1alpha1.ControllerSpec, tenantNS string) *corev1ac.PodSpecApplyConfiguration {
	if !metricsHTTPS(c) {
		return pod
	}
	target := fmt.Sprintf("https://127.0.0.1:%d%s", c.Metrics.Port, cmp.Or(c.Metrics.Path, "/metrics"))
	return pod.WithContainers(corev1ac.Container().WithName("metrics-proxy").WithImage(r.apiserverImage).
		WithCommand("/tenant-apiserver").
		WithArgs("metrics-proxy", fmt.Sprintf(":%d", metricsProxyPort), target, "/var/run/tenant/kubeconfig", tenantNS).
		WithVolumeMounts(corev1ac.VolumeMount().WithName("tenant-kubeconfig").WithMountPath("/var/run/tenant").WithReadOnly(true)).
		WithResources(corev1ac.ResourceRequirements().
			WithRequests(corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("64Mi")}).
			// Limits on both: the controllers' ResourceQuota counts them.
			WithLimits(corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(metricsProxyCPU), corev1.ResourceMemory: resource.MustParse(metricsProxyMemory)})).
		WithSecurityContext(hardenedContainer()))
}

// sidecarResources are for the tenant-apiserver binary's small modes (metrics-proxy, forward):
// ~55Mi measured, most of it the binary's own pages.
func sidecarResources() *corev1ac.ResourceRequirementsApplyConfiguration {
	return corev1ac.ResourceRequirements().
		WithRequests(corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("64Mi")}).
		WithLimits(corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")})
}

// controllerScratch: what a controller may write (to /tmp, its only writable path; logs aside).
var controllerScratch = resource.MustParse("1Gi")

func kubeconfigSecret(controller string) string { return "ctrl-" + controller + "-kubeconfig" }

// webhookName is a controller's webhook Service and its serving cert's Secret.
func webhookName(controller string) string { return "ctrl-" + controller + "-webhook" }

// registrySecret is the tenant's registry credential <name> (spec.controllers[].imagePullSecrets).
func registrySecret(name string) string { return "registry-" + name }

// probe is a tenant's probe without any host: the kubelet probes from the node, outside the
// pod's network policy (the CRD rejects hosts too; this covers objects stored before that).
func probe(p *platformv1alpha1.Probe) *corev1ac.ProbeApplyConfiguration {
	if p == nil {
		return nil
	}
	cp := p.Probe.DeepCopy()
	if cp.HTTPGet != nil {
		cp.HTTPGet.Host = ""
	}
	if cp.TCPSocket != nil {
		cp.TCPSocket.Host = ""
	}
	b, err := json.Marshal(cp) // same JSON shape as the apply configuration
	ac := &corev1ac.ProbeApplyConfiguration{}
	if err != nil || json.Unmarshal(b, ac) != nil {
		return nil
	}
	return ac
}

// certHash identifies a cert in a pod template annotation (certAnno), so a renewed one restarts the pod.
func certHash(crt []byte) string {
	sum := sha256.Sum256(crt)
	return hex.EncodeToString(sum[:8])
}

// jsonEnv decodes the JSON in environment variable key into v, if set.
func jsonEnv(key string, v any) error {
	if s := env(key, ""); s != "" {
		if err := json.Unmarshal([]byte(s), v); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func main() {
	ctrl.SetLogger(zap.New())
	platformNS := env("POD_NAMESPACE", "platform-system")
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// One replica (the leader) reconciles and ships logs; every replica serves the site, so
		// rollouts and a second replica keep it up.
		LeaderElection:          true,
		LeaderElectionID:        "platform.ctrlplane.run",
		LeaderElectionNamespace: platformNS,
		// Safe: the process exits right after the manager stops. Rollouts hand over at once.
		LeaderElectionReleaseOnCancel: true,
		HealthProbeBindAddress:        env("PROBE_ADDR", ":8082"),
	})
	if err == nil {
		err = mgr.AddHealthzCheck("ping", healthz.Ping)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Admins (e.g. "github:alice,github:bob") are always active and get /admin; DEFAULT_SIGNUP
	// (open | approval | invite) applies until an admin saves settings.
	acct := &accounts{Client: mgr.GetClient(), ns: platformNS, defaultSignup: env("DEFAULT_SIGNUP", "")}
	for _, a := range strings.Split(env("ADMINS", ""), ",") {
		if a = strings.TrimSpace(a); a != "" {
			acct.admins = append(acct.admins, a)
		}
	}
	issuer := env("OIDC_ISSUER", "") // e.g. https://auth.example.com/dex
	var issuerCA []byte
	if f := env("OIDC_CA_FILE", ""); f != "" {
		if issuerCA, err = os.ReadFile(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if issuer != "" {
		w := &web{Client: mgr.GetClient(), apiReader: mgr.GetAPIReader(), acct: acct, platformNS: platformNS, issuer: issuer, issuerCA: issuerCA,
			logsURL: env("LOGS_URL", ""), metricsURL: env("METRICS_URL", "")}
		secret, url := os.Getenv("OIDC_CLIENT_SECRET"), env("WEB_URL", "")
		err = mgr.Add(everyReplica(func(ctx context.Context) error {
			return w.serve(ctx, env("WEB_ADDR", ":8081"), secret, url)
		}))
		if err == nil { // ready once the site serves (it first waits for the OIDC issuer)
			err = mgr.AddReadyzCheck("site", func(*http.Request) error {
				if !w.serving.Load() {
					return errors.New("site not serving yet")
				}
				return nil
			})
		}
	}
	if logsURL := env("LOGS_URL", ""); logsURL != "" && err == nil { // e.g. http://victorialogs.platform-system.svc:9428
		var cs *kubernetes.Clientset
		if cs, err = kubernetes.NewForConfig(mgr.GetConfig()); err == nil {
			err = mgr.Add(&logShipper{cs: cs, vl: logsURL, http: &http.Client{Timeout: 30 * time.Second}})
		}
		if err == nil {
			err = mgr.Add(&eventShipper{Reader: mgr.GetClient(), platformNS: platformNS, vl: logsURL,
				http: &http.Client{Timeout: 30 * time.Second}, config: inClusterConfig})
		}
	}
	if err == nil {
		rec := &reconciler{
			Client:         mgr.GetClient(),
			apiReader:      mgr.GetAPIReader(),
			acct:           acct,
			platformNS:     platformNS,
			apiserverImage: env("TENANT_APISERVER_IMAGE", "tenant-apiserver:dev"),
			storageClass:   env("TENANT_STORAGE_CLASS", ""),
			pullSecrets:    strings.FieldsFunc(env("TENANT_IMAGE_PULL_SECRETS", ""), func(c rune) bool { return c == ',' }), // e.g. ghcr
			metricsURL:     env("METRICS_URL", ""),                                                                          // e.g. http://victoriametrics.platform-system.svc:8428
			logsURL:        env("LOGS_URL", ""),
			runtimeClass:   env("TENANT_RUNTIME_CLASS", ""), // e.g. gvisor; empty on kind
			domain:         env("TENANT_DOMAIN", ""),        // e.g. api.example.com
			endpointPort:   env("TENANT_ENDPOINT_PORT", "443"),
			gateway:        env("GATEWAY", "platform-system/tenants"),
			gatewayProxyNS: env("GATEWAY_PROXY_NAMESPACE", "envoy-gateway-system"),
			tunnelDomain:   env("TUNNEL_DOMAIN", ""), // e.g. tunnel.example.com
			chiselImage:    env("CHISEL_IMAGE", "jpillora/chisel:1.12.1"),
			tailscaleImage: env("TAILSCALE_IMAGE", "tailscale/tailscale:v1.102.5"),
			oidcIssuer:     issuer,
			oidcCA:         issuerCA,
		}
		err = errors.Join(
			jsonEnv("TENANT_APISERVER_RESOURCES", &rec.apiserverResources), // {"requests": {"memory": "256Mi"}, ...}
			jsonEnv("TENANT_TUNNEL_RESOURCES", &rec.tunnelResources))
		if err == nil {
			rec.storageSize, err = resource.ParseQuantity(env("TENANT_STORAGE_SIZE", "1Gi"))
		}
		if err == nil {
			rec.workers, err = strconv.Atoi(env("MAX_CONCURRENT_RECONCILES", "4"))
		}
		if err == nil {
			rec.backups, err = backupsFromEnv()
		}
		if err == nil && rec.backups != nil {
			err = mgr.Add(&backupper{Client: mgr.GetClient(), b: rec.backups, platformNS: platformNS})
		}
		if err == nil {
			err = rec.setupWithManager(mgr)
		}
	}
	if err == nil {
		err = mgr.Start(ctrl.SetupSignalHandler())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// applyAccounts enforces the owners' accounts on spec (accounts.go): owners without an active
// account lose API access, only the controllers that fit the (first active) owner's limits run,
// with their share of its CPU/memory (allocate), and a tunnel only runs if that owner may have
// one. It returns the limits applied.
func (r *reconciler) applyAccounts(ctx context.Context, tenant string, spec *platformv1alpha1.TenantSpec) limits {
	lim, active := r.acct.limitsFor(ctx, spec.Owners)
	spec.Owners = active
	if spec.Tunnel != nil && !lim.Tunnel {
		ctrl.LoggerFrom(ctx).Info("tunnel not allowed for this account, not running it", "tenant", tenant)
		spec.Tunnel = nil
	}
	var skipped []string
	if spec.Controllers, skipped, _ = allocate(spec.Controllers, lim); len(skipped) > 0 {
		ctrl.LoggerFrom(ctx).Info("controllers beyond the account's limits, not running them", "tenant", tenant, "controllers", skipped)
	}
	return lim
}

// controllerQuota caps a tenant's controller pods together (they run in PriorityClass
// controllerPriorityClass, which scopes it; the API server and tunnel aren't counted): the
// account's CPU and memory per control plane, plus room for a rolling update of the largest
// controller and for the metrics-proxy sidecars. run is what allocate kept. Without a budget for a
// resource, that one isn't capped.
func controllerQuota(ns string, l limits, run []platformv1alpha1.ControllerSpec, owner *metav1ac.OwnerReferenceApplyConfiguration) *corev1ac.ResourceQuotaApplyConfiguration {
	hard := corev1.ResourceList{corev1.ResourcePods: *resource.NewQuantity(int64(maxControllers(l)+1), resource.DecimalSI)}
	sidecars := 0 // one per HTTPS-metrics controller, and one more for its rolling update
	for _, c := range run {
		if metricsHTTPS(c) {
			sidecars++
		}
	}
	if sidecars > 0 {
		sidecars++
	}
	for name, quota := range map[corev1.ResourceName]corev1.ResourceName{corev1.ResourceCPU: corev1.ResourceLimitsCPU, corev1.ResourceMemory: corev1.ResourceLimitsMemory} {
		q, ok := budget(l, name)
		if !ok {
			continue
		}
		largest := resource.Quantity{}
		for _, c := range run {
			if lim := c.Resources.Limits[name]; lim.Cmp(largest) > 0 {
				largest = lim
			}
		}
		q.Add(largest)
		side := resource.MustParse(map[corev1.ResourceName]string{corev1.ResourceCPU: metricsProxyCPU, corev1.ResourceMemory: metricsProxyMemory}[name])
		side.Mul(int64(sidecars))
		q.Add(side)
		hard[quota] = q
	}
	return corev1ac.ResourceQuota("controllers", ns).WithOwnerReferences(owner).WithSpec(corev1ac.ResourceQuotaSpec().
		WithHard(hard).
		WithScopeSelector(corev1ac.ScopeSelector().WithMatchExpressions(corev1ac.ScopedResourceSelectorRequirement().
			WithScopeName(corev1.ResourceQuotaScopePriorityClass).WithOperator(corev1.ScopeSelectorOpIn).
			WithValues(controllerPriorityClass))))
}

// tenantsOfUser maps a changed User to the control planes its login owns.
func (r *reconciler) tenantsOfUser(ctx context.Context, o client.Object) []reconcile.Request {
	u, ok := o.(*platformv1alpha1.User)
	if !ok {
		return nil
	}
	list := &platformv1alpha1.TenantList{}
	if err := r.List(ctx, list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, t := range list.Items {
		if slices.Contains(t.Spec.Owners, u.Spec.Login) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: t.Name}})
		}
	}
	return reqs
}

// everyReplica is a manager Runnable that runs on every replica, not only the leader.
type everyReplica func(context.Context) error

func (f everyReplica) Start(ctx context.Context) error { return f(ctx) }
func (everyReplica) NeedLeaderElection() bool          { return false }

func (r *reconciler) setupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&platformv1alpha1.Tenant{}).
		// Different tenants reconcile in parallel; one tenant never does twice at once.
		WithOptions(controller.Options{MaxConcurrentReconciles: r.workers}).
		Owns(&appsv1.Deployment{}).Owns(&appsv1.StatefulSet{}).
		// An account's status or limits changed: its control planes follow.
		Watches(&platformv1alpha1.User{}, handler.EnqueueRequestsFromMapFunc(r.tenantsOfUser)).
		// A pull secret was rotated: every tenant gets the new copy.
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.tenantsOfPullSecret)).
		Complete(r)
}

// copyPullSecrets keeps a copy of each pull secret in the tenant namespace (pods can only
// reference Secrets in their own namespace) and deletes copies of names no longer configured:
// they hold registry credentials.
func (r *reconciler) copyPullSecrets(ctx context.Context, ns string, owner *metav1ac.OwnerReferenceApplyConfiguration) error {
	for _, name := range r.pullSecrets {
		src := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: r.platformNS, Name: name}, src); err != nil {
			return fmt.Errorf("pull secret %s/%s: %w", r.platformNS, name, err)
		}
		if err := r.Apply(ctx, corev1ac.Secret(name, ns).WithLabels(map[string]string{labelPullSecret: "true"}).
			WithOwnerReferences(owner).WithType(src.Type).WithData(src.Data), fieldOwner, client.ForceOwnership); err != nil {
			return err
		}
	}
	copies := &corev1.SecretList{}
	if err := r.List(ctx, copies, client.InNamespace(ns), client.HasLabels{labelPullSecret}); err != nil {
		return err
	}
	for i := range copies.Items {
		if !slices.Contains(r.pullSecrets, copies.Items[i].Name) {
			if err := client.IgnoreNotFound(r.Delete(ctx, &copies.Items[i])); err != nil {
				return err
			}
		}
	}
	return nil
}

// withPullSecrets is for pods whose images the platform chooses; see reconciler.pullSecrets.
func (r *reconciler) withPullSecrets(pod *corev1ac.PodSpecApplyConfiguration) *corev1ac.PodSpecApplyConfiguration {
	for _, name := range r.pullSecrets {
		pod.WithImagePullSecrets(corev1ac.LocalObjectReference().WithName(name))
	}
	return pod
}

// tenantsOfPullSecret maps a changed pull secret (in the platform namespace) to every Tenant.
func (r *reconciler) tenantsOfPullSecret(ctx context.Context, o client.Object) []reconcile.Request {
	if o.GetNamespace() != r.platformNS || !slices.Contains(r.pullSecrets, o.GetName()) {
		return nil
	}
	list := &platformv1alpha1.TenantList{}
	if err := r.List(ctx, list); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for _, t := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: t.Name}})
	}
	return reqs
}

// Private and special ranges: pod and service networks, LANs, CGNAT (Tailscale), loopback and
// link-local, which holds cloud metadata (169.254.169.254). Tenant code reaches these only
// through the tenant's tunnel.
var privateV4, privateV6 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15"}, // "this network", IETF (incl. some clouds' metadata), benchmarking
	[]string{"fc00::/7", "fe80::/10", "::1/128"}

// egressPolicies limit what a tenant's pods may connect to. tenant-egress, for tenant code
// (controllers, the tunnel): DNS, its own namespace (its API server, tunnel, forwards) and the
// public internet, minus the nodes' own addresses (public on a VPS); not the host API, other
// tenants, the node, or a LAN. apiserver-egress, for the tenant API server (platform code, but
// owners choose where its webhooks call): the same, plus what it needs: the host API, the
// platform's namespace (metrics and logs stores, Dex, S3) and the Gateway's proxies (the OIDC
// issuer, when its name resolves to them).
// ponytail: node and host API addresses are read on each tenant reconcile; a new node is covered
// once its tenants reconcile again (or the platform restarts).
func (r *reconciler) egressPolicies(ctx context.Context, ns string, owner *metav1ac.OwnerReferenceApplyConfiguration) (tenant, apiserver *networkingv1ac.NetworkPolicyApplyConfiguration, err error) {
	exceptV4, exceptV6 := slices.Clone(privateV4), slices.Clone(privateV6)
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes); err != nil {
		return nil, nil, err
	}
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			switch ip := net.ParseIP(a.Address); {
			case ip == nil:
			case ip.To4() != nil && !inRanges(ip, privateV4):
				exceptV4 = append(exceptV4, ip.String()+"/32")
			case ip.To4() == nil && !inRanges(ip, privateV6):
				exceptV6 = append(exceptV6, ip.String()+"/128")
			}
		}
	}
	slices.Sort(exceptV4)
	slices.Sort(exceptV6)
	udp, tcp, dns := corev1.ProtocolUDP, corev1.ProtocolTCP, intstr.FromInt32(53)
	common := []*networkingv1ac.NetworkPolicyEgressRuleApplyConfiguration{
		networkingv1ac.NetworkPolicyEgressRule().WithTo(networkingv1ac.NetworkPolicyPeer().
			WithNamespaceSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"kubernetes.io/metadata.name": "kube-system"})).
			WithPodSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"k8s-app": "kube-dns"}))).
			WithPorts(networkingv1ac.NetworkPolicyPort().WithProtocol(udp).WithPort(dns), networkingv1ac.NetworkPolicyPort().WithProtocol(tcp).WithPort(dns)),
		networkingv1ac.NetworkPolicyEgressRule().WithTo(networkingv1ac.NetworkPolicyPeer().WithPodSelector(metav1ac.LabelSelector())),
		networkingv1ac.NetworkPolicyEgressRule().WithTo(
			networkingv1ac.NetworkPolicyPeer().WithIPBlock(networkingv1ac.IPBlock().WithCIDR("0.0.0.0/0").WithExcept(slices.Compact(exceptV4)...)),
			networkingv1ac.NetworkPolicyPeer().WithIPBlock(networkingv1ac.IPBlock().WithCIDR("::/0").WithExcept(slices.Compact(exceptV6)...))),
	}
	isAPIServer := metav1ac.LabelSelectorRequirement().WithKey("app").WithValues("apiserver")
	tenant = networkingv1ac.NetworkPolicy("tenant-egress", ns).WithOwnerReferences(owner).WithSpec(networkingv1ac.NetworkPolicySpec().
		WithPodSelector(metav1ac.LabelSelector().WithMatchExpressions(isAPIServer.WithOperator(metav1.LabelSelectorOpNotIn))).
		WithPolicyTypes(networkingv1.PolicyTypeEgress).WithEgress(common...))

	inNamespace := func(name string) *networkingv1ac.NetworkPolicyEgressRuleApplyConfiguration {
		return networkingv1ac.NetworkPolicyEgressRule().WithTo(networkingv1ac.NetworkPolicyPeer().
			WithNamespaceSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"kubernetes.io/metadata.name": name})))
	}
	extra := []*networkingv1ac.NetworkPolicyEgressRuleApplyConfiguration{inNamespace(r.platformNS), inNamespace(r.gatewayProxyNS)}
	// The host API server, at its endpoints (policies apply after the Service's address is translated).
	eps := &discoveryv1.EndpointSliceList{}
	reader := cmp.Or[client.Reader](r.apiReader, r.Client)
	if err := reader.List(ctx, eps, client.InNamespace(metav1.NamespaceDefault), client.MatchingLabels{discoveryv1.LabelServiceName: "kubernetes"}); err != nil {
		return nil, nil, err
	}
	for _, s := range eps.Items {
		rule := networkingv1ac.NetworkPolicyEgressRule()
		for _, e := range s.Endpoints {
			for _, a := range e.Addresses {
				if ip := net.ParseIP(a); ip != nil {
					cidr := ip.String() + "/32"
					if ip.To4() == nil {
						cidr = ip.String() + "/128"
					}
					rule.WithTo(networkingv1ac.NetworkPolicyPeer().WithIPBlock(networkingv1ac.IPBlock().WithCIDR(cidr)))
				}
			}
		}
		for _, p := range s.Ports {
			if p.Port != nil {
				rule.WithPorts(networkingv1ac.NetworkPolicyPort().WithProtocol(tcp).WithPort(intstr.FromInt32(*p.Port)))
			}
		}
		if len(rule.To) > 0 {
			extra = append(extra, rule)
		}
	}
	apiserver = networkingv1ac.NetworkPolicy("apiserver-egress", ns).WithOwnerReferences(owner).WithSpec(networkingv1ac.NetworkPolicySpec().
		WithPodSelector(metav1ac.LabelSelector().WithMatchLabels(map[string]string{"app": "apiserver"})).
		WithPolicyTypes(networkingv1.PolicyTypeEgress).WithEgress(append(common, extra...)...))
	return tenant, apiserver, nil
}

func inRanges(ip net.IP, cidrs []string) bool {
	return slices.ContainsFunc(cidrs, func(c string) bool { _, n, err := net.ParseCIDR(c); return err == nil && n.Contains(ip) })
}
