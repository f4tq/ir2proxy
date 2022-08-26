package v1

import (
	"kapcom.adobe.com/envoy_api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	SidecarIngress struct {
		TypeURL string `json:"type_url,omitempty"`
		Name    string `json:"name,omitempty"`
	}

	GrpcService struct {
		SocketAddress envoy_api.SocketAddress `json:"socket_address,omitempty"`
	}

	ExtAuthz struct {
		GrpcService      GrpcService `json:"grpc_service,omitempty"`
		FailureModeAllow bool        `json:"failure_mode_allow,omitempty"`
	}

	CheckSettings struct {
		ContextExtensions map[string]string `json:"context_extensions,omitempty"`
	}

	ExtAuthzPerRoute struct {
		CheckSettings *CheckSettings `json:"check_settings,omitempty"`
	}

	SidecarFilters struct {
		ExtAuthz         *ExtAuthz         `json:"http.ext_authz.v3.ExtAuthz,omitempty"`
		ExtAuthzPerRoute *ExtAuthzPerRoute `json:"http.ext_authz.v3.ExtAuthzPerRoute,omitempty"`
	}

	SidecarSpec struct {
		Ingress SidecarIngress `json:"ingress,omitempty"`
		Filters SidecarFilters `json:"filters,omitempty"`
	}

	// +genclient
	// +genclient:noStatus
	// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
	Sidecar struct {
		metav1.TypeMeta   `json:",inline"`
		metav1.ObjectMeta `json:"metadata"`

		Spec SidecarSpec `json:"spec"`
	}

	// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
	SidecarList struct {
		metav1.TypeMeta `json:",inline"`
		metav1.ListMeta `json:"metadata"`

		Items []Sidecar `json:"items"`
	}
)
