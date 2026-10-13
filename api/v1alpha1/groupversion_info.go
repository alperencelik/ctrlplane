// Package v1alpha1 is the platform's API: Tenant (a control plane) and User (a platform account).
// +kubebuilder:object:generate=true
// +groupName=platform.ctrlplane.run
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "platform.ctrlplane.run", Version: "v1alpha1"}

	// SchemeBuilder adds the Go types to the GroupVersionKind scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &Tenant{}, &TenantList{}, &User{}, &UserList{})
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
