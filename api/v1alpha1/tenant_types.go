package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Tenant is a control plane: its own API server, plus controllers talking to it.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.status.id`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 50",message="name must be at most 50 characters (namespace is tenant-<name>)"
// +kubebuilder:validation:XValidation:rule="(has(self.spec) && has(self.spec.restoreFrom) ? self.spec.restoreFrom : null) == (has(oldSelf.spec) && has(oldSelf.spec.restoreFrom) ? oldSelf.spec.restoreFrom : null)",message="spec.restoreFrom can only be set when creating a Tenant"
type Tenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +optional
	Spec TenantSpec `json:"spec,omitzero"`
	// +optional
	Status TenantStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Tenant `json:"items"`
}

// TenantSpec is what the platform runs for a tenant: who owns it, its controllers and its tunnel.
type TenantSpec struct {
	// Users who manage CRDs and everything in the tenant namespace, as <connector>:<login>
	// +optional
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+:.+$`
	Owners []string `json:"owners,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=name
	Controllers []ControllerSpec `json:"controllers,omitempty"`

	// Network path from the controllers into the tenant's network (SOCKS5 via HTTPS_PROXY)
	// +optional
	Tunnel *TunnelSpec `json:"tunnel,omitempty"`

	// Restore this tenant from a backup of a tenant.
	// +optional
	RestoreFrom *RestoreSpec `json:"restoreFrom,omitempty"`
}

type RestoreSpec struct {
	// ID of the backed-up tenant (its status.id)
	// +kubebuilder:validation:Pattern=`^[a-z2-7]{10}$`
	TenantID string `json:"tenantID"`
	// Snapshot to restore (its status.backup.snapshot, e.g. 20261001T120000Z); empty = the latest
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9]{8}T[0-9]{6}Z$`
	Snapshot string `json:"snapshot,omitempty"`
}

// ControllerSpec is one controller Deployment, talking to the tenant API server.
type ControllerSpec struct {
	// +kubebuilder:validation:MaxLength=40
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +optional
	Args []string `json:"args,omitempty"`
	// Plain values only: valueFrom could read host-namespace Secrets.
	// +optional
	Env []EnvVar `json:"env,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitzero"`
	// Where the controller serves Prometheus metrics (default port 8080, /metrics); port 0 turns scraping off
	// +optional
	Metrics *MetricsSpec `json:"metrics,omitempty"`
	// Admission and conversion webhooks the controller serves: the tenant API server calls service
	// ctrl-<name>-webhook (port 443) in the tenant namespace, and trusts the cert the controller gets
	// in /tmp/k8s-webhook-server/serving-certs (controller-runtime's default)
	// +optional
	Webhook *WebhookSpec `json:"webhook,omitempty"`
	// +optional
	LivenessProbe *Probe `json:"livenessProbe,omitempty"`
	// +optional
	ReadinessProbe *Probe `json:"readinessProbe,omitempty"`
	// +optional
	StartupProbe *Probe `json:"startupProbe,omitempty"`
	// Credentials for a private image: each name is Secret registry-<name> (kubernetes.io/dockerconfigjson) in tenant-<name>, saved by the site
	// +optional
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:items:MaxLength=40
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ImagePullSecrets []string `json:"imagePullSecrets,omitempty"`
	// Scaled to 0 replicas: nothing runs (nor serves its webhooks) until it's started again; its
	// settings, credentials and share of the limits stay
	// +optional
	Stopped bool `json:"stopped,omitempty"`
}

// Probe checks the controller container. Probes run on the node, outside the pod's network
// policy, so HTTP and TCP checks can only target the pod itself.
// +kubebuilder:validation:XValidation:rule="!has(self.httpGet) || !has(self.httpGet.host)",message="httpGet.host isn't allowed: probes target the controller's pod"
// +kubebuilder:validation:XValidation:rule="!has(self.tcpSocket) || !has(self.tcpSocket.host)",message="tcpSocket.host isn't allowed: probes target the controller's pod"
type Probe struct {
	corev1.Probe `json:",inline"`
}

type EnvVar struct {
	Name string `json:"name"`
	// +optional
	Value string `json:"value"`
}

// MetricsSpec says where a controller serves metrics, scraped into the tenant's metrics.
type MetricsSpec struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +optional
	// +kubebuilder:validation:MaxLength=200
	// +kubebuilder:validation:Pattern=`^/[^\s]*$`
	Path string `json:"path,omitempty"`
	// https: behind controller-runtime's authn/authz filter (kubebuilder's secure metrics); scraped with a token of the tenant's ctrlplane-metrics service account
	// +optional
	// +kubebuilder:validation:Enum=http;https
	Scheme string `json:"scheme,omitempty"`
}

type WebhookSpec struct {
	// Where the controller serves webhooks (default 9443)
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`
}

type TunnelSpec struct {
	// +kubebuilder:validation:Enum=chisel;tailscale
	Type string `json:"type"`
	// Auth key: Secret tailscale-auth, key authkey, in tenant-<name> (reusable, ephemeral)
	// +optional
	Tailscale TailscaleSpec `json:"tailscale,omitzero"`
	// For controllers that ignore HTTPS_PROXY: Service <name>:<port> in tenant-<name> forwards to <host>:<port> through the tunnel
	// +optional
	// +kubebuilder:validation:MaxItems=20
	// +listType=map
	// +listMapKey=name
	Forwards []ForwardSpec `json:"forwards,omitempty"`
}

type TailscaleSpec struct {
	// Headscale URL; empty for Tailscale
	// +optional
	// +kubebuilder:validation:Pattern=`^https?://[^\s]+$`
	LoginServer string `json:"loginServer,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!(self.name in ['apiserver', 'tunnel'])",message="name is reserved"
type ForwardSpec struct {
	// Service name
	// +kubebuilder:validation:MaxLength=40
	// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// Host or IP in the tenant's network
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9.:-]+$`
	Host string `json:"host"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

type TenantStatus struct {
	// Stable DNS-safe tenant ID (from the UID)
	// +optional
	ID string `json:"id,omitempty"`
	// URL of the tenant API server
	// +optional
	Endpoint string `json:"endpoint,omitempty"`
	// URL chisel connectors dial (command: Secret tunnel, key connector)
	// +optional
	Tunnel string `json:"tunnel,omitempty"`
	// The latest backup attempt
	// +optional
	Backup *BackupStatus `json:"backup,omitempty"`
	// The snapshot spec.restoreFrom resolved to (both the database and the PKI come from it)
	// +optional
	RestoredSnapshot string `json:"restoredSnapshot,omitempty"`
}

type BackupStatus struct {
	// Name of the latest snapshot (restoreFrom.snapshot)
	// +optional
	Snapshot string `json:"snapshot,omitempty"`
	// When it was taken
	// +optional
	Time *metav1.Time `json:"time,omitempty"`
	// Why the latest attempt failed; empty when it succeeded
	// +optional
	Error string `json:"error,omitempty"`
}
