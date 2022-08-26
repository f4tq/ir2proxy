package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	ApiGroup    = "kapcom.adobe.io"
	ApiVersion  = "v1"
	SidecarKind = "Sidecar"
)

var (
	SchemeGroupVersion = schema.GroupVersion{
		Group:   ApiGroup,
		Version: ApiVersion,
	}
)

func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Sidecar{},
		&SidecarList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
