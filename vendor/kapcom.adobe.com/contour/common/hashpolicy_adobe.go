package common

import (
	"errors"
	"strings"

	"kapcom.adobe.com/types"
)

type Tracing struct {
	ClientSampling uint8 `json:"clientSampling,omitempty"`
	RandomSampling uint8 `json:"randomSampling,omitempty"`
}

// +k8s:deepcopy-gen=true
type HashPolicyHeader struct {
	HeaderName string `json:"headerName"`
}

// +k8s:deepcopy-gen=true
type HashPolicyCookie struct {
	Name string          `json:"name"`
	Ttl  *types.Duration `json:"ttl,omitempty"`
	Path string          `json:"path,omitempty"`
}

// +k8s:deepcopy-gen=true
type HashPolicyConnectionProperties struct {
	SourceIp bool `json:"sourceIp"`
}

// +k8s:deepcopy-gen=true
type HashPolicy struct {
	Header *HashPolicyHeader `json:"header,omitempty"`

	Cookie *HashPolicyCookie `json:"cookie,omitempty"`

	ConnectionProperties *HashPolicyConnectionProperties `json:"connectionProperties,omitempty"`

	Terminal bool `json:"terminal,omitempty"`
}

// +k8s:deepcopy-gen=true
type HeadersPolicy struct {
	Set    []HeaderValue `json:"set,omitempty"`
	Remove []string      `json:"remove,omitempty"`
}

// +k8s:deepcopy-gen=true
type HeaderValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

//
// HeadersPolicy
//
func (recv *HeadersPolicy) err(hostOk bool) error {
	if recv == nil {
		return nil
	}

	set := make(map[string]interface{}, len(recv.Set))
	for _, header := range recv.Set {
		headerLC := strings.ToLower(header.Name)
		if _, exists := set[headerLC]; exists {
			return errors.New("Duplicate Set Header " + header.Name)
		}
		if headerLC == "host" && !hostOk {
			return errors.New("Unsupported Set Header " + header.Name)
		}
		set[headerLC] = nil
	}

	rem := make(map[string]interface{}, len(recv.Remove))
	for _, header := range recv.Remove {
		headerLC := strings.ToLower(header)
		if _, exists := rem[headerLC]; exists {
			return errors.New("Duplicate Remove Header " + header)
		}
		rem[headerLC] = nil
	}
	return nil
}
