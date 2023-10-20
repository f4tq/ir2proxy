package v1

import (
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	SidecarIngress struct {
		TypeURL string `json:"type_url,omitempty"`
		Name    string `json:"name,omitempty"`
	}

	SidecarSpec struct {
		Ingress SidecarIngress `json:"ingress,omitempty"`
	}

	// +genclient
	// +genclient:noStatus
	// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
	Sidecar struct {
		meta.TypeMeta   `json:",inline"`
		meta.ObjectMeta `json:"metadata"`

		Spec SidecarSpec `json:"spec"`
	}

	// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
	SidecarList struct {
		meta.TypeMeta `json:",inline"`
		meta.ListMeta `json:"metadata"`

		Items []Sidecar `json:"items"`
	}
)
