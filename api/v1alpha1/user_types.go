package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// User is a platform account, one per login, managed from /admin.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Login",type=string,JSONPath=`.spec.login`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.spec.status`
// +kubebuilder:printcolumn:name="Control planes",type=integer,JSONPath=`.spec.limits.controlPlanes`
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	Spec UserSpec `json:"spec"`
}

// +kubebuilder:object:root=true
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []User `json:"items"`
}

type UserSpec struct {
	// As authenticated, <connector>:<name> (e.g. github:alice)
	// +kubebuilder:validation:MinLength=1
	Login string `json:"login"`
	// +kubebuilder:validation:Enum=active;pending;suspended
	Status string `json:"status"`
	// +optional
	Limits Limits `json:"limits"`
}

// Limits are what an account may use. Also stored in the platform-settings ConfigMap.
type Limits struct {
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	ControlPlanes int `json:"controlPlanes"`
	// CPU limit per control plane, shared by its controllers as they set (an even share each by
	// default); empty = not limited.
	// +optional
	CPU string `json:"cpu"`
	// Memory limit per control plane, shared like CPU.
	// +optional
	Memory string `json:"memory"`
	// Controllers per control plane; 0 = the platform default (5). Each tenant namespace gets a
	// ResourceQuota on its controller pods from this, CPU and Memory.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=20
	Controllers int `json:"controllers"`
	// May connect a network (spec.tunnel)
	// +optional
	Tunnel bool `json:"tunnel"`
}
