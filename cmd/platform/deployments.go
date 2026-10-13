package main

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

// A controller can be deployed from the operator's own deployment.yaml
// the site takes its Deployment and fills the controller form from it. Nothing of it is applied
// anywhere; what the form has no field for is ignored, and the site says what.

// controllerFromManifests is the controller the one Deployment in r's manifests (pasted YAML, a
// file or URLs, as readManifests reads them) describes. msg says what's wrong, if anything.
func controllerFromManifests(rw http.ResponseWriter, r *http.Request) (c platformv1alpha1.ControllerSpec, ignored []string, msg string) {
	objs, msg := readManifests(rw, r)
	if msg != "" {
		return c, nil, msg
	}
	var deps []*appsv1.Deployment
	for _, o := range objs {
		if o.GetKind() != "Deployment" || o.GroupVersionKind().Group != appsv1.GroupName {
			continue // the rest of an install.yaml: CRDs, RBAC, Services, ...
		}
		d := &appsv1.Deployment{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, d); err != nil {
			return c, nil, fmt.Sprintf("Deployment %s: %v", o.GetName(), err)
		}
		deps = append(deps, d)
	}
	switch len(deps) {
	case 0:
		return c, nil, "no Deployment found: paste your operator's deployment.yaml (or its install.yaml)"
	case 1:
	default:
		var names []string
		for _, d := range deps {
			names = append(names, d.Name)
		}
		return c, nil, fmt.Sprintf("%d Deployments (%s): deploy one at a time", len(deps), strings.Join(names, ", "))
	}
	c, ignored, err := controllerFromDeployment(deps[0])
	if err != nil {
		return c, nil, err.Error()
	}
	return c, ignored, ""
}

// metricsFromArgs is where a controller-runtime manager with args serves metrics, from
// kubebuilder's --metrics-bind-address ("0" turns them off) and --metrics-secure: nil without
// the address, so the default, :8080/metrics over HTTP. Without --metrics-secure, HTTPS only on
// 8443, as kubebuilder v4 scaffolds it (older projects serve HTTP). note says why an address
// can't be scraped.
// ponytail: kubebuilder's flags only; operators with their own flags set metrics by hand.
func metricsFromArgs(args []string) (m *platformv1alpha1.MetricsSpec, note string) {
	addr, secure, secureSet := "", false, false
	for i, a := range args {
		name, v, hasValue := strings.Cut(a, "=")
		switch name {
		case "--metrics-bind-address":
			if !hasValue && i+1 < len(args) {
				v = args[i+1] // --flag value
			}
			addr = v
		case "--metrics-secure":
			// A bool flag never takes the next arg: "--metrics-secure false" is true (and an arg "false").
			b, _ := strconv.ParseBool(v)
			secure, secureSet = !hasValue || b, true
		}
	}
	if addr == "" {
		return nil, ""
	}
	if addr == "0" {
		return &platformv1alpha1.MetricsSpec{Port: 0}, ""
	}
	host, port, err := net.SplitHostPort(addr)
	p, perr := strconv.ParseInt(port, 10, 32)
	if err != nil || perr != nil {
		return nil, "--metrics-bind-address " + addr
	}
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		return nil, "metrics on " + addr + " (loopback: unreachable for scraping)"
	}
	m = &platformv1alpha1.MetricsSpec{Port: int32(p)}
	if secure || !secureSet && p == 8443 {
		m.Scheme = "https"
	}
	return m, ""
}

// construct controllerSpec from a deployment
func controllerFromDeployment(d *appsv1.Deployment) (c platformv1alpha1.ControllerSpec, ignored []string, err error) {
	pod := d.Spec.Template.Spec
	if len(pod.Containers) == 0 {
		return c, nil, errors.New("the Deployment has no containers")
	}
	ct := pod.Containers[max(0, slices.IndexFunc(pod.Containers, func(ct corev1.Container) bool { return ct.Name == "manager" }))]
	c = platformv1alpha1.ControllerSpec{Name: d.Name, Image: ct.Image, Args: ct.Args}
	for _, e := range ct.Env {
		if e.ValueFrom != nil {
			ignored = append(ignored, "env "+e.Name+" (valueFrom)")
			continue
		}
		c.Env = append(c.Env, platformv1alpha1.EnvVar{Name: e.Name, Value: e.Value})
	}
	for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		if q, ok := ct.Resources.Limits[name]; ok {
			if c.Resources.Limits == nil {
				c.Resources.Limits = corev1.ResourceList{}
			}
			c.Resources.Limits[name] = q
		}
	}
	wrap := func(p *corev1.Probe) *platformv1alpha1.Probe {
		if p == nil {
			return nil
		}
		return &platformv1alpha1.Probe{Probe: *p}
	}
	c.LivenessProbe, c.ReadinessProbe, c.StartupProbe = wrap(ct.LivenessProbe), wrap(ct.ReadinessProbe), wrap(ct.StartupProbe)
	for _, p := range ct.Ports {
		if strings.Contains(p.Name, "webhook") { // kubebuilder's webhook-server
			c.Webhook = &platformv1alpha1.WebhookSpec{Port: p.ContainerPort}
		}
	}
	if m, note := metricsFromArgs(ct.Args); note != "" {
		ignored = append(ignored, note)
	} else {
		c.Metrics = m
	}
	// ponytail: a one-word command is taken to be the image's entrypoint (kubebuilder's /manager).
	if len(ct.Command) > 1 {
		ignored = append(ignored, "command")
	}
	if len(ct.EnvFrom) > 0 {
		ignored = append(ignored, "envFrom")
	}
	if len(ct.VolumeMounts) > 0 || len(pod.Volumes) > 0 {
		ignored = append(ignored, "volumes")
	}
	if len(pod.Containers) > 1 || len(pod.InitContainers) > 0 {
		ignored = append(ignored, "containers other than "+cmp.Or(ct.Name, "the first"))
	}
	if len(pod.ImagePullSecrets) > 0 {
		ignored = append(ignored, "imagePullSecrets (use Private image)")
	}
	if d.Spec.Replicas != nil && *d.Spec.Replicas > 1 {
		ignored = append(ignored, fmt.Sprintf("replicas: %d (one runs)", *d.Spec.Replicas))
	}
	return c, ignored, nil
}
