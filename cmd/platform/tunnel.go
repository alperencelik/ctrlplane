package main

// The tunnel gives a tenant's controllers a way into the tenant's own network.
// Either backend runs as Deployment "tunnel" in tenant-<name> and serves SOCKS5 on
// tunnel:1080; controllers get HTTPS_PROXY pointing at it:
//   - chisel: the tenant runs a connector (chisel client) that dials out over wss to
//     https://<tenantID>.<tunnelDomain> and opens a reverse SOCKS5 listener here.
//   - tailscale: a userspace tailscaled joins the tenant's own tailnet (Tailscale or
//     Headscale) with the auth key from Secret tailscale-auth/authkey, created by the
//     tenant; subnet routes they advertise are reachable through its SOCKS5 server.
//
// For controllers that ignore HTTPS_PROXY, spec.tunnel.forwards maps Service <name>:<port> in
// tenant-<name> to <host>:<port> in the tenant's network: a "forward" sidecar in the tunnel pod
// dials it through the pod's own SOCKS5 server (same for both backends).
// Nothing needs NET_ADMIN, and tenants' networks never share a routing table.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
	"github.com/alperencelik/ctrlplane/pkg/pki"
)

const (
	socksPort  = 1080
	chiselPort = 8443
	// forwards[i] listens on firstForwardPort+i in the tunnel pod; its Service maps port → that.
	firstForwardPort = 10000
	labelForward     = "platform.ctrlplane.run/forward"
	// The only remote a connector may open: reverse SOCKS5 on :1080 in the tunnel pod
	// (chisel matches the authfile regex against "R:<host>:<port>").
	connectorRemote = "R:0.0.0.0:1080:socks"
	connectorAccess = `^R:0\.0\.0\.0:1080$`
)

// reconcileTunnel converges the tunnel objects on spec and returns the connector URL
// (chisel only). Connector credentials go to Secret tunnel, key "connector".
func (r *reconciler) reconcileTunnel(ctx context.Context, tenant, ns, id string, tun *platformv1alpha1.TunnelSpec, ca map[string][]byte, owner *metav1ac.OwnerReferenceApplyConfiguration) (string, error) {
	if err := r.reconcileForwards(ctx, ns, tun, owner); err != nil {
		return "", err
	}
	chisel := tun != nil && tun.Type == "chisel"
	if !chisel {
		gone := []client.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tunnel"}},
			&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gateway-to-tunnel"}},
		}
		if tun == nil {
			gone = append(gone,
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tunnel"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tunnel"}})
		}
		if r.tunnelDomain != "" {
			route := &unstructured.Unstructured{}
			route.SetAPIVersion("gateway.networking.k8s.io/v1")
			route.SetKind("TLSRoute")
			route.SetNamespace(ns)
			route.SetName("tunnel")
			gone = append(gone, route)
		}
		for _, o := range gone {
			if err := r.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
				return "", err
			}
		}
		if tun == nil {
			return "", nil
		}
	}

	svc := corev1ac.ServiceSpec().WithSelector(map[string]string{"app": "tunnel"}).
		WithPorts(corev1ac.ServicePort().WithName("socks").WithPort(socksPort).WithTargetPort(intstr.FromInt32(socksPort)))
	var container *corev1ac.ContainerApplyConfiguration
	var volumes []*corev1ac.VolumeApplyConfiguration
	url, podAnnotations := "", map[string]string{}
	switch tun.Type {
	case "tailscale":
		extra := "--accept-routes"
		if tun.Tailscale.LoginServer != "" {
			extra += " --login-server=" + tun.Tailscale.LoginServer
		}
		container = corev1ac.Container().WithName("tunnel").WithImage(r.tailscaleImage).WithEnv(
			corev1ac.EnvVar().WithName("TS_USERSPACE").WithValue("true"),
			corev1ac.EnvVar().WithName("TS_SOCKS5_SERVER").WithValue(fmt.Sprintf(":%d", socksPort)),
			// Explicitly empty: in-memory state instead of a host Secret (the pod has no host credentials).
			// ponytail: re-auths on every restart, so the key must be reusable; persist state if that bites.
			corev1ac.EnvVar().WithName("TS_KUBE_SECRET").WithValue(""),
			corev1ac.EnvVar().WithName("TS_HOSTNAME").WithValue("ctrlplane-"+tenant),
			corev1ac.EnvVar().WithName("TS_EXTRA_ARGS").WithValue(extra),
			corev1ac.EnvVar().WithName("TS_AUTHKEY").WithValueFrom(corev1ac.EnvVarSource().WithSecretKeyRef(
				corev1ac.SecretKeySelector().WithName("tailscale-auth").WithKey("authkey"))))
	case "chisel":
		host := "tunnel." + ns + ".svc"
		if r.tunnelDomain != "" {
			host = id + "." + r.tunnelDomain
			url = "https://" + host
			if r.endpointPort != "443" {
				url += ":" + r.endpointPort
			}
			if err := r.applyPassthrough(ctx, ns, "tunnel", host, chiselPort, owner); err != nil {
				return "", err
			}
		}
		cert, err := r.ensureChiselSecret(ctx, ns, host, url, ca)
		if err != nil {
			return "", err
		}
		podAnnotations[certAnno] = cert // chisel reads its cert at start
		svc.WithPorts(corev1ac.ServicePort().WithName("wss").WithPort(chiselPort).WithTargetPort(intstr.FromInt32(chiselPort)))
		container = corev1ac.Container().WithName("tunnel").WithImage(r.chiselImage).WithArgs("server",
			"--reverse", "--host=0.0.0.0", fmt.Sprintf("--port=%d", chiselPort),
			"--keyfile=/etc/tunnel/key", "--authfile=/etc/tunnel/users.json",
			"--tls-cert=/etc/tunnel/tls.crt", "--tls-key=/etc/tunnel/tls.key").
			WithPorts(corev1ac.ContainerPort().WithName("wss").WithContainerPort(chiselPort)).
			WithReadinessProbe(corev1ac.Probe().WithTCPSocket(corev1ac.TCPSocketAction().WithPort(intstr.FromInt32(chiselPort)))).
			WithVolumeMounts(corev1ac.VolumeMount().WithName("tunnel").WithMountPath("/etc/tunnel").WithReadOnly(true))
		items := []*corev1ac.KeyToPathApplyConfiguration{}
		for _, k := range []string{"key", "users.json", "tls.crt", "tls.key"} {
			items = append(items, corev1ac.KeyToPath().WithKey(k).WithPath(k))
		}
		volumes = append(volumes, corev1ac.Volume().WithName("tunnel").WithSecret(
			corev1ac.SecretVolumeSource().WithSecretName("tunnel").WithItems(items...)))
	default:
		return "", fmt.Errorf("unknown spec.tunnel.type %q", tun.Type)
	}

	if err := r.Apply(ctx, corev1ac.Service("tunnel", ns).WithOwnerReferences(owner).WithSpec(svc), fieldOwner, client.ForceOwnership); err != nil {
		return "", err
	}
	labels := map[string]string{"app": "tunnel"}
	pod := r.withPullSecrets(r.hardenedPod()).
		WithContainers(container.WithSecurityContext(hardenedContainer()).WithResources(resources(r.tunnelResources))).WithVolumes(volumes...)
	if len(tun.Forwards) > 0 {
		args := []string{"forward"}
		for i, f := range tun.Forwards {
			args = append(args, fmt.Sprintf("%d=%s", firstForwardPort+i, net.JoinHostPort(f.Host, fmt.Sprint(f.Port))))
		}
		pod.WithContainers(corev1ac.Container().WithName("forward").WithImage(r.apiserverImage).
			WithCommand("/tenant-apiserver").WithArgs(args...).WithResources(sidecarResources()).WithSecurityContext(hardenedContainer()))
	}
	// Recreate: two tunnel pods behind one Service would split SOCKS traffic between them.
	return url, r.Apply(ctx, appsv1ac.Deployment("tunnel", ns).WithOwnerReferences(owner).WithSpec(appsv1ac.DeploymentSpec().
		WithReplicas(1).WithStrategy(appsv1ac.DeploymentStrategy().WithType(appsv1.RecreateDeploymentStrategyType)).
		WithSelector(metav1ac.LabelSelector().WithMatchLabels(labels)).
		WithTemplate(corev1ac.PodTemplateSpec().WithLabels(labels).WithAnnotations(podAnnotations).WithSpec(pod))), fieldOwner, client.ForceOwnership)
}

// ensureChiselSecret creates the chisel server's SSH key and connector credentials once,
// and (re-)issues its TLS cert from the tenant CA when host changes or it nears expiry; it
// returns the cert's certHash. The connector
// command pins the SSH key fingerprint, which authenticates the server before the
// password is sent, so the connector can skip TLS verification of the tenant CA.
func (r *reconciler) ensureChiselSecret(ctx context.Context, ns, host, url string, ca map[string][]byte) (string, error) {
	s := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: "tunnel"}, s)
	if apierrors.IsNotFound(err) {
		key, fp, err := pki.SSHKey()
		if err != nil {
			return "", err
		}
		auth := "connector:" + rand.Text()
		users, _ := json.Marshal(map[string][]string{auth: {connectorAccess}})
		s = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tunnel"},
			Data: map[string][]byte{"key": key, "fingerprint": []byte(fp), "auth": []byte(auth), "users.json": users}}
		if err := r.Create(ctx, s); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	d, changed := s.Data, false
	if !pki.Current(d["tls.crt"], host) {
		if d["tls.crt"], d["tls.key"], err = pki.ServingCert(ca["ca.crt"], ca["ca.key"], []string{host}); err != nil {
			return "", err
		}
		changed = true
	}
	cmd := fmt.Sprintf("docker run -d --name ctrlplane-connector --restart=always %s client --auth %s --fingerprint %s --tls-skip-verify %s %s",
		r.chiselImage, d["auth"], d["fingerprint"], url, connectorRemote)
	if string(d["connector"]) != cmd {
		d["connector"], changed = []byte(cmd), true
	}
	if changed {
		return certHash(d["tls.crt"]), r.Update(ctx, s)
	}
	return certHash(d["tls.crt"]), nil
}

// reconcileForwards keeps one Service per spec.tunnel.forwards entry, pointing at the tunnel
// pod's forward sidecar, and deletes the rest.
func (r *reconciler) reconcileForwards(ctx context.Context, ns string, tun *platformv1alpha1.TunnelSpec, owner *metav1ac.OwnerReferenceApplyConfiguration) error {
	want := map[string]bool{}
	if tun != nil {
		for i, f := range tun.Forwards {
			want[f.Name] = true
			if err := r.Apply(ctx, corev1ac.Service(f.Name, ns).WithLabels(map[string]string{labelForward: "true"}).
				WithOwnerReferences(owner).WithSpec(corev1ac.ServiceSpec().WithSelector(map[string]string{"app": "tunnel"}).
				WithPorts(corev1ac.ServicePort().WithName("tcp").WithPort(f.Port).WithTargetPort(intstr.FromInt32(int32(firstForwardPort+i))))),
				fieldOwner, client.ForceOwnership); err != nil {
				return err
			}
		}
	}
	svcs := &corev1.ServiceList{}
	if err := r.List(ctx, svcs, client.InNamespace(ns), client.HasLabels{labelForward}); err != nil {
		return err
	}
	for i := range svcs.Items {
		if !want[svcs.Items[i].Name] {
			if err := client.IgnoreNotFound(r.Delete(ctx, &svcs.Items[i])); err != nil {
				return err
			}
		}
	}
	return nil
}
