package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

// kubebuilder's config/manager/manager.yaml, as `make build-installer` renders it.
func kubebuilderDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "guestbook-controller-manager", Namespace: "guestbook-system"},
		Spec: appsv1.DeploymentSpec{Replicas: new(int32(1)), Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			ServiceAccountName: "guestbook-controller-manager",
			SecurityContext:    &corev1.PodSecurityContext{RunAsNonRoot: new(true)},
			Containers: []corev1.Container{{
				Name: "manager", Image: "ghcr.io/you/guestbook:v1", Command: []string{"/manager"},
				Args:  []string{"--leader-elect", "--health-probe-bind-address=:8081"},
				Env:   []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "debug"}, {Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{}}},
				Ports: []corev1.ContainerPort{{Name: "webhook-server", ContainerPort: 9443}},
				Resources: corev1.ResourceRequirements{
					Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m")}},
				LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"}}},
			}},
		}}},
	}
}

func TestControllerFromDeployment(t *testing.T) {
	c, ignored, err := controllerFromDeployment(kubebuilderDeployment())
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "guestbook-controller-manager" || c.Image != "ghcr.io/you/guestbook:v1" ||
		!slices.Equal(c.Args, []string{"--leader-elect", "--health-probe-bind-address=:8081"}) {
		t.Errorf("got %+v", c)
	}
	if len(c.Env) != 1 || c.Env[0] != (platformv1alpha1.EnvVar{Name: "LOG_LEVEL", Value: "debug"}) {
		t.Errorf("env = %v, want LOG_LEVEL only", c.Env)
	}
	if q := c.Resources.Limits[corev1.ResourceCPU]; q.String() != "500m" || c.Resources.Requests != nil {
		t.Errorf("resources = %+v, want the limits only", c.Resources)
	}
	if c.Webhook == nil || c.Webhook.Port != 9443 || c.LivenessProbe == nil || c.LivenessProbe.HTTPGet.Path != "/healthz" {
		t.Errorf("webhook %+v, liveness %+v", c.Webhook, c.LivenessProbe)
	}
	// The one-word command (the entrypoint), the service account and security context aren't worth a mention.
	if !slices.Equal(ignored, []string{"env TOKEN (valueFrom)"}) {
		t.Errorf("ignored = %q", ignored)
	}

	d := kubebuilderDeployment()
	d.Spec.Replicas = new(int32(3))
	d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers, corev1.Container{Name: "kube-rbac-proxy"})
	if _, ignored, _ := controllerFromDeployment(d); !slices.Equal(ignored, []string{"env TOKEN (valueFrom)", "containers other than manager", "replicas: 3 (one runs)"}) {
		t.Errorf("ignored = %q", ignored)
	}
	d.Spec.Template.Spec.Containers = nil
	if _, _, err := controllerFromDeployment(d); err == nil {
		t.Error("no containers: want an error")
	}
}

func TestMetricsFromArgs(t *testing.T) {
	for args, want := range map[string]string{
		"--leader-elect": "<default>",
		"--metrics-bind-address=:8443 --leader-elect":         "8443 https", // kubebuilder v4's scaffold
		"--metrics-bind-address=:8080":                        "8080 ",      // older projects: HTTP
		"--metrics-bind-address=:8080 --metrics-secure":       "8080 https",
		"--metrics-bind-address=:8443 --metrics-secure=false": "8443 ",
		"--metrics-bind-address=:8080 --metrics-secure false": "8080 https", // Go's flags: true, plus an arg
		"--metrics-bind-address=:8080 --metrics-secure=1":     "8080 https",
		"--metrics-bind-address :9090":                        "9090 ",
		"--metrics-bind-address=0":                            "0 ",
		"--metrics-bind-address=127.0.0.1:8080":               "<note>", // v3's, behind kube-rbac-proxy
	} {
		m, note := metricsFromArgs(strings.Fields(args))
		got := "<default>"
		switch {
		case note != "":
			got = "<note>"
		case m != nil:
			got = fmt.Sprintf("%d %s", m.Port, m.Scheme)
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", args, got, want)
		}
	}
}
