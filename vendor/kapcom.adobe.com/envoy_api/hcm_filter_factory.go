package envoy_api

import (
	"encoding/json"
	"errors"
	"fmt"
)

// HcmTypedConfigFactory accounts for the vast number of HTTPTypedFilterConfigs that are very often based
//
//	on protobufs that DO NOT Marshal/Unmarshal correctly due to the use of `oneof` in protobuf definitions.
//	The HTTPFilterTypedConfig  in strict_types aliases, and effectively delegates, to HcmTypedConfigFactory.
//	If an entry for  'type' exists in filterTypeConverter, unmarshal get passed to the registered handler
type (
	HcmTypedConfigFactory struct {
		Type    string `json:"@type,omitempty"`
		TypeURL string `json:"type_url,omitempty"`
		config  interface{}

		Value HTTPFilterTypedConfigValue `json:"value,omitempty"`

		// wellknown.Router
		SuppressEnvoyHeaders bool `json:"suppress_envoy_headers,omitempty"`

		// wellknown.HTTPExternalAuthorization
		GrpcServices     GrpcServices `json:"grpc_service,omitempty"`
		FailureModeAllow bool         `json:"failure_mode_allow,omitempty"`
	}
)

// Config -- return the instantiated object
func (recv *HcmTypedConfigFactory) Config() interface{} {
	return recv.config
}

func (recv *HcmTypedConfigFactory) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	typeInf, ok := allFields["@type"]
	if !ok {
		return errors.New("missing filter @type in httpfiltertypedconfig")
	}
	typ, ok := typeInf.(string)
	if !ok {
		return errors.New("type not a string")
	}

	if converter, ok := filterTypeConverter[typ]; ok {
		// TODO: eventually, each type config should register a marshal/unmarshal
		extraneousFields := map[string]interface {
		}{"@type": nil}
		// many typedfilter configs are based on protobuf which doesn't include #type
		for key := range allFields {
			if _, exists := extraneousFields[key]; exists {
				delete(allFields, key)
			}
		}
		rr, err := json.Marshal(allFields)
		if err != nil {
			return err
		}
		ifc, err := converter.Unmarshal(rr)
		if err != nil {
			return fmt.Errorf("HTTPFilterTypedConfig::UnmarshalJSON converter[%s] failed", typ)
		}
		recv.Type = typ
		recv.TypeURL = typ
		recv.config = ifc
		return nil
	}

	definedFields := map[string]interface {
	}{"@type": nil, "type_url": nil, "value": nil, "suppress_envoy_headers": nil, "grpc_service": nil, "failure_mode_allow": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPFilterTypedConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type                 string                     `json:"@type,omitempty"`
		TypeURL              string                     `json:"type_url,omitempty"`
		Value                HTTPFilterTypedConfigValue `json:"value,omitempty"`
		SuppressEnvoyHeaders bool                       `json:"suppress_envoy_headers,omitempty"`
		GrpcServices         GrpcServices               `json:"grpc_service,omitempty"`
		FailureModeAllow     bool                       `json:"failure_mode_allow,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPFilterTypedConfig" + err.Error())
	}
	recv.Type = anon.Type
	recv.TypeURL = anon.TypeURL
	recv.Value = anon.Value
	recv.SuppressEnvoyHeaders = anon.SuppressEnvoyHeaders
	recv.GrpcServices = anon.GrpcServices
	recv.FailureModeAllow = anon.FailureModeAllow
	return nil
}
func (a HcmTypedConfigFactory) Compare(b HcmTypedConfigFactory) error {
	if a.Type != b.Type {
		return fmt.Errorf(".HTTPFilterTypedConfig.Type: %v != %v", a.Type, b.Type)
	}
	if a.TypeURL != b.TypeURL {
		return fmt.Errorf(".HTTPFilterTypedConfig.TypeURL: %v != %v", a.TypeURL, b.TypeURL)
	}
	if converter, ok := filterTypeConverter[a.Type]; ok {
		err := converter.Compare(a.config, b.config)
		if err != nil {
			return fmt.Errorf(".HTTPFilterTypedConfig.config: %v != %v", a.config, b.config)
		}
		return nil
	}
	if err := a.Value.Compare(b.Value); err != nil {
		return errors.New(".HTTPFilterTypedConfig" + err.Error())
	}
	if a.SuppressEnvoyHeaders != b.SuppressEnvoyHeaders {
		return fmt.Errorf(".HTTPFilterTypedConfig.SuppressEnvoyHeaders: %v != %v", a.SuppressEnvoyHeaders, b.SuppressEnvoyHeaders)
	}
	if err := a.GrpcServices.Compare(b.GrpcServices); err != nil {
		return errors.New(".HTTPFilterTypedConfig" + err.Error())
	}
	if a.FailureModeAllow != b.FailureModeAllow {
		return fmt.Errorf(".HTTPFilterTypedConfig.FailureModeAllow: %v != %v", a.FailureModeAllow, b.FailureModeAllow)
	}
	return nil
}
