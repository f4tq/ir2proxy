package envoy_api

import (
	"encoding/json"
	"errors"
	"fmt"
)

func (recv *DataSource) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"inline_bytes": nil, "inline_string": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".DataSource JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		InlineBytes  string `json:"inline_bytes,omitempty"`
		InlineString string `json:"inline_string,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".DataSource" + err.Error())
	}
	recv.InlineBytes = anon.InlineBytes
	recv.InlineString = anon.InlineString
	return nil
}
func (a DataSource) Compare(b DataSource) error {
	if a.InlineBytes != b.InlineBytes {
		return fmt.Errorf(".DataSource.InlineBytes: %v != %v", a.InlineBytes, b.InlineBytes)
	}
	if a.InlineString != b.InlineString {
		return fmt.Errorf(".DataSource.InlineString: %v != %v", a.InlineString, b.InlineString)
	}
	return nil
}
func (recv *SocketAddress) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"address": nil, "port_value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".SocketAddress JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Address   string `json:"address,omitempty"`
		PortValue int    `json:"port_value,omitempty" nocompare`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".SocketAddress" + err.Error())
	}
	recv.Address = anon.Address
	recv.PortValue = anon.PortValue
	return nil
}
func (a SocketAddress) Compare(b SocketAddress) error {
	if a.Address != b.Address {
		return fmt.Errorf(".SocketAddress.Address: %v != %v", a.Address, b.Address)
	}
	return nil
}
func (recv *Address) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"socket_address": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Address JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		SocketAddress SocketAddress `json:"socket_address,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Address" + err.Error())
	}
	recv.SocketAddress = anon.SocketAddress
	return nil
}
func (a Address) Compare(b Address) error {
	if err := a.SocketAddress.Compare(b.SocketAddress); err != nil {
		return errors.New(".Address" + err.Error())
	}
	return nil
}
func (recv *Endpoint) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"address": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Endpoint JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Address Address `json:"address,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Endpoint" + err.Error())
	}
	recv.Address = anon.Address
	return nil
}
func (a Endpoint) Compare(b Endpoint) error {
	if err := a.Address.Compare(b.Address); err != nil {
		return errors.New(".Endpoint" + err.Error())
	}
	return nil
}
func (recv *LbEndpoint) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"endpoint": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".LbEndpoint JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Endpoint Endpoint `json:"endpoint,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".LbEndpoint" + err.Error())
	}
	recv.Endpoint = anon.Endpoint
	return nil
}
func (a LbEndpoint) Compare(b LbEndpoint) error {
	if err := a.Endpoint.Compare(b.Endpoint); err != nil {
		return errors.New(".LbEndpoint" + err.Error())
	}
	return nil
}
func (recv *Endpoints) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"lb_endpoints": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Endpoints JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		LbEndpoints []LbEndpoint `json:"lb_endpoints,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Endpoints" + err.Error())
	}
	recv.LbEndpoints = anon.LbEndpoints
	return nil
}
func (a Endpoints) Compare(b Endpoints) error {
	if len(a.LbEndpoints) != len(b.LbEndpoints) {
		return errors.New(".Endpoints.LbEndpoints mismatching lengths")
	}
	for i := range a.LbEndpoints {
		if err := a.LbEndpoints[i].Compare(b.LbEndpoints[i]); err != nil {
			return errors.New(".Endpoints" + err.Error())
		}
	}
	return nil
}
func (recv *LoadAssignment) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"cluster_name": nil, "endpoints": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".LoadAssignment JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		ClusterName string      `json:"cluster_name,omitempty" nocompare`
		Endpoints   []Endpoints `json:"endpoints,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".LoadAssignment" + err.Error())
	}
	recv.ClusterName = anon.ClusterName
	recv.Endpoints = anon.Endpoints
	return nil
}
func (a LoadAssignment) Compare(b LoadAssignment) error {
	if len(a.Endpoints) != len(b.Endpoints) {
		return errors.New(".LoadAssignment.Endpoints mismatching lengths")
	}
	for i := range a.Endpoints {
		if err := a.Endpoints[i].Compare(b.Endpoints[i]); err != nil {
			return errors.New(".LoadAssignment" + err.Error())
		}
	}
	return nil
}
func (recv *APIConfigSource) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"api_type": nil, "grpc_services": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".APIConfigSource JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		APIType      string         `json:"api_type,omitempty"`
		GrpcServices []GrpcServices `json:"grpc_services,omitempty" kapcom:"forcecompare"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".APIConfigSource" + err.Error())
	}
	recv.APIType = anon.APIType
	recv.GrpcServices = anon.GrpcServices
	return nil
}
func (a APIConfigSource) Compare(b APIConfigSource) error {
	if a.APIType != b.APIType {
		return fmt.Errorf(".APIConfigSource.APIType: %v != %v", a.APIType, b.APIType)
	}
	if len(a.GrpcServices) != len(b.GrpcServices) {
		return errors.New(".APIConfigSource.GrpcServices mismatching lengths")
	}
	for i := range a.GrpcServices {
		if err := a.GrpcServices[i].Compare(b.GrpcServices[i]); err != nil {
			return errors.New(".APIConfigSource" + err.Error())
		}
	}
	return nil
}
func (recv *ADSConfigSource) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ADSConfigSource JSON contains unknown key: " + key)
		}
	}
	anon := struct{}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ADSConfigSource" + err.Error())
	}
	return nil
}
func (a ADSConfigSource) Compare(b ADSConfigSource) error {
	return nil
}
func (recv *ConfigSource) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"api_config_source": nil, "ads": nil, "initial_fetch_timeout": nil, "resource_api_version": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ConfigSource JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		APIConfigSource     APIConfigSource `json:"api_config_source,omitempty"`
		ADSConfigSource     ADSConfigSource `json:"ads,omitempty"`
		InitialFetchTimeout string          `json:"initial_fetch_timeout,omitempty"`
		ResourceApiVersion  string          `json:"resource_api_version,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ConfigSource" + err.Error())
	}
	recv.APIConfigSource = anon.APIConfigSource
	recv.ADSConfigSource = anon.ADSConfigSource
	recv.InitialFetchTimeout = anon.InitialFetchTimeout
	recv.ResourceApiVersion = anon.ResourceApiVersion
	return nil
}
func (a ConfigSource) Compare(b ConfigSource) error {
	if err := a.APIConfigSource.Compare(b.APIConfigSource); err != nil {
		return errors.New(".ConfigSource" + err.Error())
	}
	if err := a.ADSConfigSource.Compare(b.ADSConfigSource); err != nil {
		return errors.New(".ConfigSource" + err.Error())
	}
	if a.InitialFetchTimeout != b.InitialFetchTimeout {
		return fmt.Errorf(".ConfigSource.InitialFetchTimeout: %v != %v", a.InitialFetchTimeout, b.InitialFetchTimeout)
	}
	if a.ResourceApiVersion != b.ResourceApiVersion {
		return fmt.Errorf(".ConfigSource.ResourceApiVersion: %v != %v", a.ResourceApiVersion, b.ResourceApiVersion)
	}
	return nil
}
func (recv *EdsClusterConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"eds_config": nil, "service_name": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".EdsClusterConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		EdsConfig   ConfigSource `json:"eds_config,omitempty"`
		ServiceName string       `json:"service_name,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".EdsClusterConfig" + err.Error())
	}
	recv.EdsConfig = anon.EdsConfig
	recv.ServiceName = anon.ServiceName
	return nil
}
func (a EdsClusterConfig) Compare(b EdsClusterConfig) error {
	if err := a.EdsConfig.Compare(b.EdsConfig); err != nil {
		return errors.New(".EdsClusterConfig" + err.Error())
	}
	if a.ServiceName != b.ServiceName {
		return fmt.Errorf(".EdsClusterConfig.ServiceName: %v != %v", a.ServiceName, b.ServiceName)
	}
	return nil
}
func (recv *Thresholds) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"max_connections": nil, "max_requests": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Thresholds JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		MaxConnections int `json:"max_connections,omitempty"`
		MaxRequests    int `json:"max_requests,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Thresholds" + err.Error())
	}
	recv.MaxConnections = anon.MaxConnections
	recv.MaxRequests = anon.MaxRequests
	return nil
}
func (a Thresholds) Compare(b Thresholds) error {
	if a.MaxConnections != b.MaxConnections {
		return fmt.Errorf(".Thresholds.MaxConnections: %v != %v", a.MaxConnections, b.MaxConnections)
	}
	if a.MaxRequests != b.MaxRequests {
		return fmt.Errorf(".Thresholds.MaxRequests: %v != %v", a.MaxRequests, b.MaxRequests)
	}
	return nil
}
func (recv *CircuitBreakers) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"thresholds": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".CircuitBreakers JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Thresholds []Thresholds `json:"thresholds,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".CircuitBreakers" + err.Error())
	}
	recv.Thresholds = anon.Thresholds
	return nil
}
func (a CircuitBreakers) Compare(b CircuitBreakers) error {
	if len(a.Thresholds) != len(b.Thresholds) {
		return errors.New(".CircuitBreakers.Thresholds mismatching lengths")
	}
	for i := range a.Thresholds {
		if err := a.Thresholds[i].Compare(b.Thresholds[i]); err != nil {
			return errors.New(".CircuitBreakers" + err.Error())
		}
	}
	return nil
}
func (recv *HealthyPanicThreshold) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HealthyPanicThreshold JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Value int `json:"value,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HealthyPanicThreshold" + err.Error())
	}
	recv.Value = anon.Value
	return nil
}
func (a HealthyPanicThreshold) Compare(b HealthyPanicThreshold) error {
	if a.Value != b.Value {
		return fmt.Errorf(".HealthyPanicThreshold.Value: %v != %v", a.Value, b.Value)
	}
	return nil
}
func (recv *CommonLbConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"healthy_panic_threshold": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".CommonLbConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		HealthyPanicThreshold HealthyPanicThreshold `json:"healthy_panic_threshold,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".CommonLbConfig" + err.Error())
	}
	recv.HealthyPanicThreshold = anon.HealthyPanicThreshold
	return nil
}
func (a CommonLbConfig) Compare(b CommonLbConfig) error {
	if err := a.HealthyPanicThreshold.Compare(b.HealthyPanicThreshold); err != nil {
		return errors.New(".CommonLbConfig" + err.Error())
	}
	return nil
}
func (recv *HTTP2ProtocolOptions) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTP2ProtocolOptions JSON contains unknown key: " + key)
		}
	}
	anon := struct{}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTP2ProtocolOptions" + err.Error())
	}
	return nil
}
func (a HTTP2ProtocolOptions) Compare(b HTTP2ProtocolOptions) error {
	return nil
}
func (recv *CommonHTTPProtocolOptions) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"idle_timeout": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".CommonHTTPProtocolOptions JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		IdleTimeout string `json:"idle_timeout,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".CommonHTTPProtocolOptions" + err.Error())
	}
	recv.IdleTimeout = anon.IdleTimeout
	return nil
}
func (a CommonHTTPProtocolOptions) Compare(b CommonHTTPProtocolOptions) error {
	if a.IdleTimeout != b.IdleTimeout {
		return fmt.Errorf(".CommonHTTPProtocolOptions.IdleTimeout: %v != %v", a.IdleTimeout, b.IdleTimeout)
	}
	return nil
}
func (recv *ExpectedStatus) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"start": nil, "end": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ExpectedStatus JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Start string `json:"start,omitempty"`
		End   string `json:"end,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ExpectedStatus" + err.Error())
	}
	recv.Start = anon.Start
	recv.End = anon.End
	return nil
}
func (a ExpectedStatus) Compare(b ExpectedStatus) error {
	if a.Start != b.Start {
		return fmt.Errorf(".ExpectedStatus.Start: %v != %v", a.Start, b.Start)
	}
	if a.End != b.End {
		return fmt.Errorf(".ExpectedStatus.End: %v != %v", a.End, b.End)
	}
	return nil
}
func (recv *HTTPHealthCheck) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"host": nil, "path": nil, "expected_statuses": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPHealthCheck JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Host             string           `json:"host,omitempty" nocompare`
		Path             string           `json:"path,omitempty"`
		ExpectedStatuses []ExpectedStatus `json:"expected_statuses,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPHealthCheck" + err.Error())
	}
	recv.Host = anon.Host
	recv.Path = anon.Path
	recv.ExpectedStatuses = anon.ExpectedStatuses
	return nil
}
func (a HTTPHealthCheck) Compare(b HTTPHealthCheck) error {
	if a.Path != b.Path {
		return fmt.Errorf(".HTTPHealthCheck.Path: %v != %v", a.Path, b.Path)
	}
	if len(a.ExpectedStatuses) != len(b.ExpectedStatuses) {
		return errors.New(".HTTPHealthCheck.ExpectedStatuses mismatching lengths")
	}
	for i := range a.ExpectedStatuses {
		if err := a.ExpectedStatuses[i].Compare(b.ExpectedStatuses[i]); err != nil {
			return errors.New(".HTTPHealthCheck" + err.Error())
		}
	}
	return nil
}
func (recv *HealthCheck) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"timeout": nil, "interval": nil, "unhealthy_threshold": nil, "healthy_threshold": nil, "http_health_check": nil, "interval_jitter_percent": nil, "initial_jitter": nil, "reuse_connection": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HealthCheck JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Timeout               string          `json:"timeout,omitempty"`
		Interval              string          `json:"interval,omitempty"`
		UnhealthyThreshold    int             `json:"unhealthy_threshold,omitempty"`
		HealthyThreshold      int             `json:"healthy_threshold,omitempty"`
		HTTPHealthCheck       HTTPHealthCheck `json:"http_health_check,omitempty"`
		IntervalJitterPercent int             `json:"interval_jitter_percent,omitempty"`
		InitialJitter         string          `json:"initial_jitter,omitempty"`
		ReuseConnection       *bool           `json:"reuse_connection,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HealthCheck" + err.Error())
	}
	recv.Timeout = anon.Timeout
	recv.Interval = anon.Interval
	recv.UnhealthyThreshold = anon.UnhealthyThreshold
	recv.HealthyThreshold = anon.HealthyThreshold
	recv.HTTPHealthCheck = anon.HTTPHealthCheck
	recv.IntervalJitterPercent = anon.IntervalJitterPercent
	recv.InitialJitter = anon.InitialJitter
	recv.ReuseConnection = anon.ReuseConnection
	return nil
}
func (a HealthCheck) Compare(b HealthCheck) error {
	if a.Timeout != b.Timeout {
		return fmt.Errorf(".HealthCheck.Timeout: %v != %v", a.Timeout, b.Timeout)
	}
	if a.Interval != b.Interval {
		return fmt.Errorf(".HealthCheck.Interval: %v != %v", a.Interval, b.Interval)
	}
	if a.UnhealthyThreshold != b.UnhealthyThreshold {
		return fmt.Errorf(".HealthCheck.UnhealthyThreshold: %v != %v", a.UnhealthyThreshold, b.UnhealthyThreshold)
	}
	if a.HealthyThreshold != b.HealthyThreshold {
		return fmt.Errorf(".HealthCheck.HealthyThreshold: %v != %v", a.HealthyThreshold, b.HealthyThreshold)
	}
	if err := a.HTTPHealthCheck.Compare(b.HTTPHealthCheck); err != nil {
		return errors.New(".HealthCheck" + err.Error())
	}
	if a.IntervalJitterPercent != b.IntervalJitterPercent {
		return fmt.Errorf(".HealthCheck.IntervalJitterPercent: %v != %v", a.IntervalJitterPercent, b.IntervalJitterPercent)
	}
	if a.InitialJitter != b.InitialJitter {
		return fmt.Errorf(".HealthCheck.InitialJitter: %v != %v", a.InitialJitter, b.InitialJitter)
	}
	if a.ReuseConnection == nil && b.ReuseConnection == nil {
	} else if a.ReuseConnection != nil && b.ReuseConnection != nil {
		if *a.ReuseConnection != *b.ReuseConnection {
			return fmt.Errorf(".HealthCheck.ReuseConnection: %v != %v", a.ReuseConnection, b.ReuseConnection)
		}
	} else {
		return errors.New(".HealthCheck.ReuseConnection is nil on one object and not nil on the other")
	}
	return nil
}
func (recv *TCPKeepalive) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"keepalive_probes": nil, "keepalive_time": nil, "keepalive_interval": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TCPKeepalive JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		KeepaliveProbes   int `json:"keepalive_probes,omitempty"`
		KeepaliveTime     int `json:"keepalive_time,omitempty"`
		KeepaliveInterval int `json:"keepalive_interval,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TCPKeepalive" + err.Error())
	}
	recv.KeepaliveProbes = anon.KeepaliveProbes
	recv.KeepaliveTime = anon.KeepaliveTime
	recv.KeepaliveInterval = anon.KeepaliveInterval
	return nil
}
func (a TCPKeepalive) Compare(b TCPKeepalive) error {
	if a.KeepaliveProbes != b.KeepaliveProbes {
		return fmt.Errorf(".TCPKeepalive.KeepaliveProbes: %v != %v", a.KeepaliveProbes, b.KeepaliveProbes)
	}
	if a.KeepaliveTime != b.KeepaliveTime {
		return fmt.Errorf(".TCPKeepalive.KeepaliveTime: %v != %v", a.KeepaliveTime, b.KeepaliveTime)
	}
	if a.KeepaliveInterval != b.KeepaliveInterval {
		return fmt.Errorf(".TCPKeepalive.KeepaliveInterval: %v != %v", a.KeepaliveInterval, b.KeepaliveInterval)
	}
	return nil
}
func (recv *UpstreamConnectionOptions) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"tcp_keepalive": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".UpstreamConnectionOptions JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		TCPKeepalive TCPKeepalive `json:"tcp_keepalive,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".UpstreamConnectionOptions" + err.Error())
	}
	recv.TCPKeepalive = anon.TCPKeepalive
	return nil
}
func (a UpstreamConnectionOptions) Compare(b UpstreamConnectionOptions) error {
	if err := a.TCPKeepalive.Compare(b.TCPKeepalive); err != nil {
		return errors.New(".UpstreamConnectionOptions" + err.Error())
	}
	return nil
}
func (recv *Cluster) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "type": nil, "name": nil, "eds_cluster_config": nil, "upstream_connection_options": nil, "connect_timeout": nil, "circuit_breakers": nil, "common_lb_config": nil, "alt_stat_name": nil, "common_http_protocol_options": nil, "http2_protocol_options": nil, "drain_connections_on_host_removal": nil, "health_checks": nil, "lb_policy": nil, "transport_socket": nil, "load_assignment": nil, "typed_extension_protocol_options": nil, "ignore_health_on_host_removal": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Cluster JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type                          string                    `json:"@type,omitempty" nocompare`
		ClusterType                   string                    `json:"type,omitempty"`
		Name                          string                    `json:"name,omitempty" nocompare`
		EdsClusterConfig              EdsClusterConfig          `json:"eds_cluster_config,omitempty" nocompare`
		UpstreamConnectionOptions     UpstreamConnectionOptions `json:"upstream_connection_options,omitempty"`
		ConnectTimeout                string                    `json:"connect_timeout,omitempty"`
		CircuitBreakers               CircuitBreakers           `json:"circuit_breakers,omitempty"`
		CommonLbConfig                CommonLbConfig            `json:"common_lb_config,omitempty"`
		AltStatName                   string                    `json:"alt_stat_name,omitempty"`
		CommonHTTPProtocolOptions     CommonHTTPProtocolOptions `json:"common_http_protocol_options,omitempty"`
		HTTP2ProtocolOptions          *HTTP2ProtocolOptions     `json:"http2_protocol_options,omitempty"`
		DrainConnectionsOnHostRemoval bool                      `json:"drain_connections_on_host_removal,omitempty" nocompare`
		HealthChecks                  []HealthCheck             `json:"health_checks,omitempty"`
		LbPolicy                      string                    `json:"lb_policy,omitempty"`
		TransportSocket               *TransportSocket          `json:"transport_socket,omitempty"`
		LoadAssignment                LoadAssignment            `json:"load_assignment,omitempty"`
		TypedExtensionProtocolOptions map[string]*Any           `json:"typed_extension_protocol_options,omitempty" nocompare`
		IgnoreHealthOnHostRemoval     bool                      `json:"ignore_health_on_host_removal,omitempty" nocompare`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Cluster" + err.Error())
	}
	recv.Type = anon.Type
	recv.ClusterType = anon.ClusterType
	recv.Name = anon.Name
	recv.EdsClusterConfig = anon.EdsClusterConfig
	recv.UpstreamConnectionOptions = anon.UpstreamConnectionOptions
	recv.ConnectTimeout = anon.ConnectTimeout
	recv.CircuitBreakers = anon.CircuitBreakers
	recv.CommonLbConfig = anon.CommonLbConfig
	recv.AltStatName = anon.AltStatName
	recv.CommonHTTPProtocolOptions = anon.CommonHTTPProtocolOptions
	recv.HTTP2ProtocolOptions = anon.HTTP2ProtocolOptions
	recv.DrainConnectionsOnHostRemoval = anon.DrainConnectionsOnHostRemoval
	recv.HealthChecks = anon.HealthChecks
	recv.LbPolicy = anon.LbPolicy
	recv.TransportSocket = anon.TransportSocket
	recv.LoadAssignment = anon.LoadAssignment
	recv.TypedExtensionProtocolOptions = anon.TypedExtensionProtocolOptions
	recv.IgnoreHealthOnHostRemoval = anon.IgnoreHealthOnHostRemoval
	return nil
}
func (a Cluster) Compare(b Cluster) error {
	if a.ClusterType != b.ClusterType {
		return fmt.Errorf(".Cluster.ClusterType: %v != %v", a.ClusterType, b.ClusterType)
	}
	if err := a.UpstreamConnectionOptions.Compare(b.UpstreamConnectionOptions); err != nil {
		return errors.New(".Cluster" + err.Error())
	}
	if a.ConnectTimeout != b.ConnectTimeout {
		return fmt.Errorf(".Cluster.ConnectTimeout: %v != %v", a.ConnectTimeout, b.ConnectTimeout)
	}
	if err := a.CircuitBreakers.Compare(b.CircuitBreakers); err != nil {
		return errors.New(".Cluster" + err.Error())
	}
	if err := a.CommonLbConfig.Compare(b.CommonLbConfig); err != nil {
		return errors.New(".Cluster" + err.Error())
	}
	if a.AltStatName != b.AltStatName {
		return fmt.Errorf(".Cluster.AltStatName: %v != %v", a.AltStatName, b.AltStatName)
	}
	if err := a.CommonHTTPProtocolOptions.Compare(b.CommonHTTPProtocolOptions); err != nil {
		return errors.New(".Cluster" + err.Error())
	}
	if a.HTTP2ProtocolOptions == nil && b.HTTP2ProtocolOptions == nil {
	} else if a.HTTP2ProtocolOptions != nil && b.HTTP2ProtocolOptions != nil {
		if err := (*a.HTTP2ProtocolOptions).Compare(*b.HTTP2ProtocolOptions); err != nil {
			return errors.New(".Cluster" + err.Error())
		}
	} else {
		return errors.New(".Cluster.HTTP2ProtocolOptions is nil on one object and not nil on the other")
	}
	if len(a.HealthChecks) != len(b.HealthChecks) {
		return errors.New(".Cluster.HealthChecks mismatching lengths")
	}
	for i := range a.HealthChecks {
		if err := a.HealthChecks[i].Compare(b.HealthChecks[i]); err != nil {
			return errors.New(".Cluster" + err.Error())
		}
	}
	if a.LbPolicy != b.LbPolicy {
		return fmt.Errorf(".Cluster.LbPolicy: %v != %v", a.LbPolicy, b.LbPolicy)
	}
	if a.TransportSocket == nil && b.TransportSocket == nil {
	} else if a.TransportSocket != nil && b.TransportSocket != nil {
		if err := (*a.TransportSocket).Compare(*b.TransportSocket); err != nil {
			return errors.New(".Cluster" + err.Error())
		}
	} else {
		return errors.New(".Cluster.TransportSocket is nil on one object and not nil on the other")
	}
	if err := a.LoadAssignment.Compare(b.LoadAssignment); err != nil {
		return errors.New(".Cluster" + err.Error())
	}
	return nil
}
func (recv *RdsConfigSource) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"config_source": nil, "route_config_name": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".RdsConfigSource JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		ConfigSource    ConfigSource `json:"config_source,omitempty"`
		RouteConfigName string       `json:"route_config_name,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".RdsConfigSource" + err.Error())
	}
	recv.ConfigSource = anon.ConfigSource
	recv.RouteConfigName = anon.RouteConfigName
	return nil
}
func (a RdsConfigSource) Compare(b RdsConfigSource) error {
	if err := a.ConfigSource.Compare(b.ConfigSource); err != nil {
		return errors.New(".RdsConfigSource" + err.Error())
	}
	if a.RouteConfigName != b.RouteConfigName {
		return fmt.Errorf(".RdsConfigSource.RouteConfigName: %v != %v", a.RouteConfigName, b.RouteConfigName)
	}
	return nil
}
func (recv *HTTPFilterTypedConfigValue) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"path": nil, "max_bytes": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPFilterTypedConfigValue JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Path     string  `json:"path,omitempty"`
		MaxBytes float64 `json:"max_bytes,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPFilterTypedConfigValue" + err.Error())
	}
	recv.Path = anon.Path
	recv.MaxBytes = anon.MaxBytes
	return nil
}
func (a HTTPFilterTypedConfigValue) Compare(b HTTPFilterTypedConfigValue) error {
	if a.Path != b.Path {
		return fmt.Errorf(".HTTPFilterTypedConfigValue.Path: %v != %v", a.Path, b.Path)
	}
	if a.MaxBytes != b.MaxBytes {
		return fmt.Errorf(".HTTPFilterTypedConfigValue.MaxBytes: %v != %v", a.MaxBytes, b.MaxBytes)
	}
	return nil
}
func (recv *HTTPFilter) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "typed_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPFilter JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name        string                `json:"name,omitempty" nocompare`
		TypedConfig HTTPFilterTypedConfig `json:"typed_config,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPFilter" + err.Error())
	}
	recv.Name = anon.Name
	recv.TypedConfig = anon.TypedConfig
	return nil
}
func (a HTTPFilter) Compare(b HTTPFilter) error {
	if a.TypedConfig != b.TypedConfig {
		return fmt.Errorf(".HTTPFilter.TypedConfig: %v != %v", a.TypedConfig, b.TypedConfig)
	}
	return nil
}
func (recv *HTTPProtocolOptions) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"accept_http_10": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPProtocolOptions JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		AcceptHTTP10 bool `json:"accept_http_10,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPProtocolOptions" + err.Error())
	}
	recv.AcceptHTTP10 = anon.AcceptHTTP10
	return nil
}
func (a HTTPProtocolOptions) Compare(b HTTPProtocolOptions) error {
	if a.AcceptHTTP10 != b.AcceptHTTP10 {
		return fmt.Errorf(".HTTPProtocolOptions.AcceptHTTP10: %v != %v", a.AcceptHTTP10, b.AcceptHTTP10)
	}
	return nil
}
func (recv *LogFormat) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"json_format": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".LogFormat JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		JSONFormat JSONFormat `json:"json_format,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".LogFormat" + err.Error())
	}
	recv.JSONFormat = anon.JSONFormat
	return nil
}
func (a LogFormat) Compare(b LogFormat) error {
	if err := a.JSONFormat.Compare(b.JSONFormat); err != nil {
		return errors.New(".LogFormat" + err.Error())
	}
	return nil
}
func (recv *JSONFormat) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"authority": nil, "bytes_received": nil, "bytes_sent": nil, "downstream_local_address": nil, "downstream_remote_address": nil, "duration": nil, "method": nil, "path": nil, "protocol": nil, "request_duration": nil, "requested_server_name": nil, "request_id": nil, "response_code": nil, "response_code_details": nil, "response_duration": nil, "response_flags": nil, "response_tx_duration": nil, "@timestamp": nil, "uber_trace_id": nil, "upstream_cluster": nil, "upstream_host": nil, "upstream_local_address": nil, "upstream_service_time": nil, "user_agent": nil, "x_forwarded_for": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".JSONFormat JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Authority               string `json:"authority,omitempty"`
		BytesReceived           string `json:"bytes_received,omitempty"`
		BytesSent               string `json:"bytes_sent,omitempty"`
		DownstreamLocalAddress  string `json:"downstream_local_address,omitempty"`
		DownstreamRemoteAddress string `json:"downstream_remote_address,omitempty"`
		Duration                string `json:"duration,omitempty"`
		Method                  string `json:"method,omitempty"`
		Path                    string `json:"path,omitempty"`
		Protocol                string `json:"protocol,omitempty"`
		RequestDuration         string `json:"request_duration,omitempty"`
		RequestedServerName     string `json:"requested_server_name,omitempty"`
		RequestID               string `json:"request_id,omitempty"`
		ResponseCode            string `json:"response_code,omitempty"`
		ResponseCodeDetails     string `json:"response_code_details,omitempty"`
		ResponseDuration        string `json:"response_duration,omitempty"`
		ResponseFlags           string `json:"response_flags,omitempty"`
		ResponseTxDuration      string `json:"response_tx_duration,omitempty"`
		Timestamp               string `json:"@timestamp,omitempty"`
		UberTraceID             string `json:"uber_trace_id,omitempty"`
		UpstreamCluster         string `json:"upstream_cluster,omitempty"`
		UpstreamHost            string `json:"upstream_host,omitempty"`
		UpstreamLocalAddress    string `json:"upstream_local_address,omitempty"`
		UpstreamServiceTime     string `json:"upstream_service_time,omitempty"`
		UserAgent               string `json:"user_agent,omitempty"`
		XForwardedFor           string `json:"x_forwarded_for,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".JSONFormat" + err.Error())
	}
	recv.Authority = anon.Authority
	recv.BytesReceived = anon.BytesReceived
	recv.BytesSent = anon.BytesSent
	recv.DownstreamLocalAddress = anon.DownstreamLocalAddress
	recv.DownstreamRemoteAddress = anon.DownstreamRemoteAddress
	recv.Duration = anon.Duration
	recv.Method = anon.Method
	recv.Path = anon.Path
	recv.Protocol = anon.Protocol
	recv.RequestDuration = anon.RequestDuration
	recv.RequestedServerName = anon.RequestedServerName
	recv.RequestID = anon.RequestID
	recv.ResponseCode = anon.ResponseCode
	recv.ResponseCodeDetails = anon.ResponseCodeDetails
	recv.ResponseDuration = anon.ResponseDuration
	recv.ResponseFlags = anon.ResponseFlags
	recv.ResponseTxDuration = anon.ResponseTxDuration
	recv.Timestamp = anon.Timestamp
	recv.UberTraceID = anon.UberTraceID
	recv.UpstreamCluster = anon.UpstreamCluster
	recv.UpstreamHost = anon.UpstreamHost
	recv.UpstreamLocalAddress = anon.UpstreamLocalAddress
	recv.UpstreamServiceTime = anon.UpstreamServiceTime
	recv.UserAgent = anon.UserAgent
	recv.XForwardedFor = anon.XForwardedFor
	return nil
}
func (a JSONFormat) Compare(b JSONFormat) error {
	if a.Authority != b.Authority {
		return fmt.Errorf(".JSONFormat.Authority: %v != %v", a.Authority, b.Authority)
	}
	if a.BytesReceived != b.BytesReceived {
		return fmt.Errorf(".JSONFormat.BytesReceived: %v != %v", a.BytesReceived, b.BytesReceived)
	}
	if a.BytesSent != b.BytesSent {
		return fmt.Errorf(".JSONFormat.BytesSent: %v != %v", a.BytesSent, b.BytesSent)
	}
	if a.DownstreamLocalAddress != b.DownstreamLocalAddress {
		return fmt.Errorf(".JSONFormat.DownstreamLocalAddress: %v != %v", a.DownstreamLocalAddress, b.DownstreamLocalAddress)
	}
	if a.DownstreamRemoteAddress != b.DownstreamRemoteAddress {
		return fmt.Errorf(".JSONFormat.DownstreamRemoteAddress: %v != %v", a.DownstreamRemoteAddress, b.DownstreamRemoteAddress)
	}
	if a.Duration != b.Duration {
		return fmt.Errorf(".JSONFormat.Duration: %v != %v", a.Duration, b.Duration)
	}
	if a.Method != b.Method {
		return fmt.Errorf(".JSONFormat.Method: %v != %v", a.Method, b.Method)
	}
	if a.Path != b.Path {
		return fmt.Errorf(".JSONFormat.Path: %v != %v", a.Path, b.Path)
	}
	if a.Protocol != b.Protocol {
		return fmt.Errorf(".JSONFormat.Protocol: %v != %v", a.Protocol, b.Protocol)
	}
	if a.RequestDuration != b.RequestDuration {
		return fmt.Errorf(".JSONFormat.RequestDuration: %v != %v", a.RequestDuration, b.RequestDuration)
	}
	if a.RequestedServerName != b.RequestedServerName {
		return fmt.Errorf(".JSONFormat.RequestedServerName: %v != %v", a.RequestedServerName, b.RequestedServerName)
	}
	if a.RequestID != b.RequestID {
		return fmt.Errorf(".JSONFormat.RequestID: %v != %v", a.RequestID, b.RequestID)
	}
	if a.ResponseCode != b.ResponseCode {
		return fmt.Errorf(".JSONFormat.ResponseCode: %v != %v", a.ResponseCode, b.ResponseCode)
	}
	if a.ResponseCodeDetails != b.ResponseCodeDetails {
		return fmt.Errorf(".JSONFormat.ResponseCodeDetails: %v != %v", a.ResponseCodeDetails, b.ResponseCodeDetails)
	}
	if a.ResponseDuration != b.ResponseDuration {
		return fmt.Errorf(".JSONFormat.ResponseDuration: %v != %v", a.ResponseDuration, b.ResponseDuration)
	}
	if a.ResponseFlags != b.ResponseFlags {
		return fmt.Errorf(".JSONFormat.ResponseFlags: %v != %v", a.ResponseFlags, b.ResponseFlags)
	}
	if a.ResponseTxDuration != b.ResponseTxDuration {
		return fmt.Errorf(".JSONFormat.ResponseTxDuration: %v != %v", a.ResponseTxDuration, b.ResponseTxDuration)
	}
	if a.Timestamp != b.Timestamp {
		return fmt.Errorf(".JSONFormat.Timestamp: %v != %v", a.Timestamp, b.Timestamp)
	}
	if a.UberTraceID != b.UberTraceID {
		return fmt.Errorf(".JSONFormat.UberTraceID: %v != %v", a.UberTraceID, b.UberTraceID)
	}
	if a.UpstreamCluster != b.UpstreamCluster {
		return fmt.Errorf(".JSONFormat.UpstreamCluster: %v != %v", a.UpstreamCluster, b.UpstreamCluster)
	}
	if a.UpstreamHost != b.UpstreamHost {
		return fmt.Errorf(".JSONFormat.UpstreamHost: %v != %v", a.UpstreamHost, b.UpstreamHost)
	}
	if a.UpstreamLocalAddress != b.UpstreamLocalAddress {
		return fmt.Errorf(".JSONFormat.UpstreamLocalAddress: %v != %v", a.UpstreamLocalAddress, b.UpstreamLocalAddress)
	}
	if a.UpstreamServiceTime != b.UpstreamServiceTime {
		return fmt.Errorf(".JSONFormat.UpstreamServiceTime: %v != %v", a.UpstreamServiceTime, b.UpstreamServiceTime)
	}
	if a.UserAgent != b.UserAgent {
		return fmt.Errorf(".JSONFormat.UserAgent: %v != %v", a.UserAgent, b.UserAgent)
	}
	if a.XForwardedFor != b.XForwardedFor {
		return fmt.Errorf(".JSONFormat.XForwardedFor: %v != %v", a.XForwardedFor, b.XForwardedFor)
	}
	return nil
}
func (recv *AccessLogTypedConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "path": nil, "json_format": nil, "log_format": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".AccessLogTypedConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type       string     `json:"@type,omitempty"`
		Path       string     `json:"path,omitempty"`
		JSONFormat JSONFormat `json:"json_format,omitempty"`
		LogFormat  LogFormat  `json:"log_format,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".AccessLogTypedConfig" + err.Error())
	}
	recv.Type = anon.Type
	recv.Path = anon.Path
	recv.JSONFormat = anon.JSONFormat
	recv.LogFormat = anon.LogFormat
	return nil
}
func (a AccessLogTypedConfig) Compare(b AccessLogTypedConfig) error {
	if a.Type != b.Type {
		return fmt.Errorf(".AccessLogTypedConfig.Type: %v != %v", a.Type, b.Type)
	}
	if a.Path != b.Path {
		return fmt.Errorf(".AccessLogTypedConfig.Path: %v != %v", a.Path, b.Path)
	}
	if err := a.JSONFormat.Compare(b.JSONFormat); err != nil {
		return errors.New(".AccessLogTypedConfig" + err.Error())
	}
	if err := a.LogFormat.Compare(b.LogFormat); err != nil {
		return errors.New(".AccessLogTypedConfig" + err.Error())
	}
	return nil
}
func (recv *AccessLog) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "typed_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".AccessLog JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name        string               `json:"name,omitempty"`
		TypedConfig AccessLogTypedConfig `json:"typed_config,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".AccessLog" + err.Error())
	}
	recv.Name = anon.Name
	recv.TypedConfig = anon.TypedConfig
	return nil
}
func (a AccessLog) Compare(b AccessLog) error {
	if a.Name != b.Name {
		return fmt.Errorf(".AccessLog.Name: %v != %v", a.Name, b.Name)
	}
	if err := a.TypedConfig.Compare(b.TypedConfig); err != nil {
		return errors.New(".AccessLog" + err.Error())
	}
	return nil
}
func (recv *TracingSampler) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"type": nil, "param": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TracingSampler JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type  string `json:"type,omitempty"`
		Param int    `json:"param,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TracingSampler" + err.Error())
	}
	recv.Type = anon.Type
	recv.Param = anon.Param
	return nil
}
func (a TracingSampler) Compare(b TracingSampler) error {
	if a.Type != b.Type {
		return fmt.Errorf(".TracingSampler.Type: %v != %v", a.Type, b.Type)
	}
	if a.Param != b.Param {
		return fmt.Errorf(".TracingSampler.Param: %v != %v", a.Param, b.Param)
	}
	return nil
}
func (recv *TracingReporter) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"localAgentHostPort": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TracingReporter JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		LocalAgentHostPort string `json:"localAgentHostPort,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TracingReporter" + err.Error())
	}
	recv.LocalAgentHostPort = anon.LocalAgentHostPort
	return nil
}
func (a TracingReporter) Compare(b TracingReporter) error {
	if a.LocalAgentHostPort != b.LocalAgentHostPort {
		return fmt.Errorf(".TracingReporter.LocalAgentHostPort: %v != %v", a.LocalAgentHostPort, b.LocalAgentHostPort)
	}
	return nil
}
func (recv *TracingHeaders) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"jaegerDebugHeader": nil, "jaegerBaggageHeader": nil, "TraceContextHeaderName": nil, "traceBaggageHeaderPrefix": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TracingHeaders JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		JaegerDebugHeader        string `json:"jaegerDebugHeader,omitempty"`
		JaegerBaggageHeader      string `json:"jaegerBaggageHeader,omitempty"`
		TraceContextHeaderName   string `json:"TraceContextHeaderName,omitempty"`
		TraceBaggageHeaderPrefix string `json:"traceBaggageHeaderPrefix,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TracingHeaders" + err.Error())
	}
	recv.JaegerDebugHeader = anon.JaegerDebugHeader
	recv.JaegerBaggageHeader = anon.JaegerBaggageHeader
	recv.TraceContextHeaderName = anon.TraceContextHeaderName
	recv.TraceBaggageHeaderPrefix = anon.TraceBaggageHeaderPrefix
	return nil
}
func (a TracingHeaders) Compare(b TracingHeaders) error {
	if a.JaegerDebugHeader != b.JaegerDebugHeader {
		return fmt.Errorf(".TracingHeaders.JaegerDebugHeader: %v != %v", a.JaegerDebugHeader, b.JaegerDebugHeader)
	}
	if a.JaegerBaggageHeader != b.JaegerBaggageHeader {
		return fmt.Errorf(".TracingHeaders.JaegerBaggageHeader: %v != %v", a.JaegerBaggageHeader, b.JaegerBaggageHeader)
	}
	if a.TraceContextHeaderName != b.TraceContextHeaderName {
		return fmt.Errorf(".TracingHeaders.TraceContextHeaderName: %v != %v", a.TraceContextHeaderName, b.TraceContextHeaderName)
	}
	if a.TraceBaggageHeaderPrefix != b.TraceBaggageHeaderPrefix {
		return fmt.Errorf(".TracingHeaders.TraceBaggageHeaderPrefix: %v != %v", a.TraceBaggageHeaderPrefix, b.TraceBaggageHeaderPrefix)
	}
	return nil
}
func (recv *TracingBaggageRestrictions) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"denyBaggageOnInitializationFailure": nil, "hostPort": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TracingBaggageRestrictions JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		DenyBaggageOnInitializationFailure bool   `json:"denyBaggageOnInitializationFailure,omitempty"`
		HostPort                           string `json:"hostPort,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TracingBaggageRestrictions" + err.Error())
	}
	recv.DenyBaggageOnInitializationFailure = anon.DenyBaggageOnInitializationFailure
	recv.HostPort = anon.HostPort
	return nil
}
func (a TracingBaggageRestrictions) Compare(b TracingBaggageRestrictions) error {
	if a.DenyBaggageOnInitializationFailure != b.DenyBaggageOnInitializationFailure {
		return fmt.Errorf(".TracingBaggageRestrictions.DenyBaggageOnInitializationFailure: %v != %v", a.DenyBaggageOnInitializationFailure, b.DenyBaggageOnInitializationFailure)
	}
	if a.HostPort != b.HostPort {
		return fmt.Errorf(".TracingBaggageRestrictions.HostPort: %v != %v", a.HostPort, b.HostPort)
	}
	return nil
}
func (recv *TracingLibraryConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"propagation_format": nil, "sampler": nil, "reporter": nil, "headers": nil, "baggage_restrictions": nil, "service_name": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TracingLibraryConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		PropagationFormat   string                     `json:"propagation_format,omitempty"`
		Sampler             TracingSampler             `json:"sampler,omitempty"`
		Reporter            TracingReporter            `json:"reporter,omitempty"`
		Headers             TracingHeaders             `json:"headers,omitempty"`
		BaggageRestrictions TracingBaggageRestrictions `json:"baggage_restrictions,omitempty"`
		ServiceName         string                     `json:"service_name,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TracingLibraryConfig" + err.Error())
	}
	recv.PropagationFormat = anon.PropagationFormat
	recv.Sampler = anon.Sampler
	recv.Reporter = anon.Reporter
	recv.Headers = anon.Headers
	recv.BaggageRestrictions = anon.BaggageRestrictions
	recv.ServiceName = anon.ServiceName
	return nil
}
func (a TracingLibraryConfig) Compare(b TracingLibraryConfig) error {
	if a.PropagationFormat != b.PropagationFormat {
		return fmt.Errorf(".TracingLibraryConfig.PropagationFormat: %v != %v", a.PropagationFormat, b.PropagationFormat)
	}
	if err := a.Sampler.Compare(b.Sampler); err != nil {
		return errors.New(".TracingLibraryConfig" + err.Error())
	}
	if err := a.Reporter.Compare(b.Reporter); err != nil {
		return errors.New(".TracingLibraryConfig" + err.Error())
	}
	if err := a.Headers.Compare(b.Headers); err != nil {
		return errors.New(".TracingLibraryConfig" + err.Error())
	}
	if err := a.BaggageRestrictions.Compare(b.BaggageRestrictions); err != nil {
		return errors.New(".TracingLibraryConfig" + err.Error())
	}
	if a.ServiceName != b.ServiceName {
		return fmt.Errorf(".TracingLibraryConfig.ServiceName: %v != %v", a.ServiceName, b.ServiceName)
	}
	return nil
}
func (recv *HTTPTracingConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"config": nil, "library": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPTracingConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Config  TracingLibraryConfig `json:"config,omitempty"`
		Library string               `json:"library,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPTracingConfig" + err.Error())
	}
	recv.Config = anon.Config
	recv.Library = anon.Library
	return nil
}
func (a HTTPTracingConfig) Compare(b HTTPTracingConfig) error {
	if err := a.Config.Compare(b.Config); err != nil {
		return errors.New(".HTTPTracingConfig" + err.Error())
	}
	if a.Library != b.Library {
		return fmt.Errorf(".HTTPTracingConfig.Library: %v != %v", a.Library, b.Library)
	}
	return nil
}
func (recv *HTTPTracing) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"config": nil, "name": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPTracing JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Config HTTPTracingConfig `json:"config,omitempty"`
		Name   string            `json:"name,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPTracing" + err.Error())
	}
	recv.Config = anon.Config
	recv.Name = anon.Name
	return nil
}
func (a HTTPTracing) Compare(b HTTPTracing) error {
	if err := a.Config.Compare(b.Config); err != nil {
		return errors.New(".HTTPTracing" + err.Error())
	}
	if a.Name != b.Name {
		return fmt.Errorf(".HTTPTracing.Name: %v != %v", a.Name, b.Name)
	}
	return nil
}
func (recv *Tracing) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"http": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Tracing JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		HTTP HTTPTracing `json:"http,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Tracing" + err.Error())
	}
	recv.HTTP = anon.HTTP
	return nil
}
func (a Tracing) Compare(b Tracing) error {
	if err := a.HTTP.Compare(b.HTTP); err != nil {
		return errors.New(".Tracing" + err.Error())
	}
	return nil
}
func (recv *FiltersTypedConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "stat_prefix": nil, "server_name": nil, "rds": nil, "route_config": nil, "http_filters": nil, "http_protocol_options": nil, "access_log": nil, "tracing": nil, "use_remote_address": nil, "generate_request_id": nil, "request_timeout": nil, "max_request_headers_kb": nil, "normalize_path": nil, "merge_slashes": nil, "idle_timeout": nil, "cluster": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".FiltersTypedConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type                string              `json:"@type,omitempty" nocompare`
		StatPrefix          string              `json:"stat_prefix,omitempty" nocompare`
		ServerName          string              `json:"server_name,omitempty" nocompare`
		RdsConfigSource     RdsConfigSource     `json:"rds,omitempty" nocompare`
		RouteConfig         RouteConfig         `json:"route_config,omitempty"`
		HTTPFilters         []HTTPFilter        `json:"http_filters,omitempty"`
		HTTPProtocolOptions HTTPProtocolOptions `json:"http_protocol_options,omitempty"`
		AccessLog           []AccessLog         `json:"access_log,omitempty" nocompare`
		Tracing             Tracing             `json:"tracing,omitempty" nocompare`
		UseRemoteAddress    bool                `json:"use_remote_address,omitempty"`
		GenerateRequestID   bool                `json:"generate_request_id,omitempty"`
		RequestTimeout      string              `json:"request_timeout,omitempty"`
		MaxRequestHeadersKb int                 `json:"max_request_headers_kb,omitempty"`
		NormalizePath       bool                `json:"normalize_path,omitempty"`
		MergeSlashes        bool                `json:"merge_slashes,omitempty"`
		IdleTimeout         string              `json:"idle_timeout,omitempty"`
		Cluster             string              `json:"cluster,omitempty" nocompare`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".FiltersTypedConfig" + err.Error())
	}
	recv.Type = anon.Type
	recv.StatPrefix = anon.StatPrefix
	recv.ServerName = anon.ServerName
	recv.RdsConfigSource = anon.RdsConfigSource
	recv.RouteConfig = anon.RouteConfig
	recv.HTTPFilters = anon.HTTPFilters
	recv.HTTPProtocolOptions = anon.HTTPProtocolOptions
	recv.AccessLog = anon.AccessLog
	recv.Tracing = anon.Tracing
	recv.UseRemoteAddress = anon.UseRemoteAddress
	recv.GenerateRequestID = anon.GenerateRequestID
	recv.RequestTimeout = anon.RequestTimeout
	recv.MaxRequestHeadersKb = anon.MaxRequestHeadersKb
	recv.NormalizePath = anon.NormalizePath
	recv.MergeSlashes = anon.MergeSlashes
	recv.IdleTimeout = anon.IdleTimeout
	recv.Cluster = anon.Cluster
	return nil
}
func (a FiltersTypedConfig) Compare(b FiltersTypedConfig) error {
	if err := a.RouteConfig.Compare(b.RouteConfig); err != nil {
		return errors.New(".FiltersTypedConfig" + err.Error())
	}
	if len(a.HTTPFilters) != len(b.HTTPFilters) {
		return errors.New(".FiltersTypedConfig.HTTPFilters mismatching lengths")
	}
	for i := range a.HTTPFilters {
		if err := a.HTTPFilters[i].Compare(b.HTTPFilters[i]); err != nil {
			return errors.New(".FiltersTypedConfig" + err.Error())
		}
	}
	if err := a.HTTPProtocolOptions.Compare(b.HTTPProtocolOptions); err != nil {
		return errors.New(".FiltersTypedConfig" + err.Error())
	}
	if a.UseRemoteAddress != b.UseRemoteAddress {
		return fmt.Errorf(".FiltersTypedConfig.UseRemoteAddress: %v != %v", a.UseRemoteAddress, b.UseRemoteAddress)
	}
	if a.GenerateRequestID != b.GenerateRequestID {
		return fmt.Errorf(".FiltersTypedConfig.GenerateRequestID: %v != %v", a.GenerateRequestID, b.GenerateRequestID)
	}
	if a.RequestTimeout != b.RequestTimeout {
		return fmt.Errorf(".FiltersTypedConfig.RequestTimeout: %v != %v", a.RequestTimeout, b.RequestTimeout)
	}
	if a.MaxRequestHeadersKb != b.MaxRequestHeadersKb {
		return fmt.Errorf(".FiltersTypedConfig.MaxRequestHeadersKb: %v != %v", a.MaxRequestHeadersKb, b.MaxRequestHeadersKb)
	}
	if a.NormalizePath != b.NormalizePath {
		return fmt.Errorf(".FiltersTypedConfig.NormalizePath: %v != %v", a.NormalizePath, b.NormalizePath)
	}
	if a.MergeSlashes != b.MergeSlashes {
		return fmt.Errorf(".FiltersTypedConfig.MergeSlashes: %v != %v", a.MergeSlashes, b.MergeSlashes)
	}
	if a.IdleTimeout != b.IdleTimeout {
		return fmt.Errorf(".FiltersTypedConfig.IdleTimeout: %v != %v", a.IdleTimeout, b.IdleTimeout)
	}
	return nil
}
func (recv *Filters) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "typed_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Filters JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name        string             `json:"name,omitempty" nocompare`
		TypedConfig FiltersTypedConfig `json:"typed_config,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Filters" + err.Error())
	}
	recv.Name = anon.Name
	recv.TypedConfig = anon.TypedConfig
	return nil
}
func (a Filters) Compare(b Filters) error {
	if err := a.TypedConfig.Compare(b.TypedConfig); err != nil {
		return errors.New(".Filters" + err.Error())
	}
	return nil
}
func (recv *FilterChainMatch) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"server_names": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".FilterChainMatch JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		ServerNames []string `json:"server_names,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".FilterChainMatch" + err.Error())
	}
	recv.ServerNames = anon.ServerNames
	return nil
}
func (a FilterChainMatch) Compare(b FilterChainMatch) error {
	if len(a.ServerNames) != len(b.ServerNames) {
		return errors.New(".FilterChainMatch.ServerNames mismatching lengths")
	}
	for i := range a.ServerNames {
		if a.ServerNames[i] != b.ServerNames[i] {
			return fmt.Errorf(".FilterChainMatch.ServerNames: %v != %v", a.ServerNames, b.ServerNames)
		}
	}
	return nil
}
func (recv *TLSParams) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"tls_minimum_protocol_version": nil, "tls_maximum_protocol_version": nil, "cipher_suites": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TLSParams JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		TLSMinimumProtocolVersion string   `json:"tls_minimum_protocol_version,omitempty"`
		TLSMaximumProtocolVersion string   `json:"tls_maximum_protocol_version,omitempty"`
		CipherSuites              []string `json:"cipher_suites,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TLSParams" + err.Error())
	}
	recv.TLSMinimumProtocolVersion = anon.TLSMinimumProtocolVersion
	recv.TLSMaximumProtocolVersion = anon.TLSMaximumProtocolVersion
	recv.CipherSuites = anon.CipherSuites
	return nil
}
func (a TLSParams) Compare(b TLSParams) error {
	if a.TLSMinimumProtocolVersion != b.TLSMinimumProtocolVersion {
		return fmt.Errorf(".TLSParams.TLSMinimumProtocolVersion: %v != %v", a.TLSMinimumProtocolVersion, b.TLSMinimumProtocolVersion)
	}
	if a.TLSMaximumProtocolVersion != b.TLSMaximumProtocolVersion {
		return fmt.Errorf(".TLSParams.TLSMaximumProtocolVersion: %v != %v", a.TLSMaximumProtocolVersion, b.TLSMaximumProtocolVersion)
	}
	if len(a.CipherSuites) != len(b.CipherSuites) {
		return errors.New(".TLSParams.CipherSuites mismatching lengths")
	}
	for i := range a.CipherSuites {
		if a.CipherSuites[i] != b.CipherSuites[i] {
			return fmt.Errorf(".TLSParams.CipherSuites: %v != %v", a.CipherSuites, b.CipherSuites)
		}
	}
	return nil
}
func (recv *TLSCertificateSdsSecretConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "sds_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TLSCertificateSdsSecretConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name      string       `json:"name,omitempty"`
		SdsConfig ConfigSource `json:"sds_config,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TLSCertificateSdsSecretConfig" + err.Error())
	}
	recv.Name = anon.Name
	recv.SdsConfig = anon.SdsConfig
	return nil
}
func (a TLSCertificateSdsSecretConfig) Compare(b TLSCertificateSdsSecretConfig) error {
	if a.Name != b.Name {
		return fmt.Errorf(".TLSCertificateSdsSecretConfig.Name: %v != %v", a.Name, b.Name)
	}
	if err := a.SdsConfig.Compare(b.SdsConfig); err != nil {
		return errors.New(".TLSCertificateSdsSecretConfig" + err.Error())
	}
	return nil
}
func (recv *ValidationContext) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"trusted_ca": nil, "trust_chain_verification": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ValidationContext JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		TrustedCA              DataSource `json:"trusted_ca,omitempty"`
		TrustChainVerification string     `json:"trust_chain_verification,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ValidationContext" + err.Error())
	}
	recv.TrustedCA = anon.TrustedCA
	recv.TrustChainVerification = anon.TrustChainVerification
	return nil
}
func (a ValidationContext) Compare(b ValidationContext) error {
	if err := a.TrustedCA.Compare(b.TrustedCA); err != nil {
		return errors.New(".ValidationContext" + err.Error())
	}
	if a.TrustChainVerification != b.TrustChainVerification {
		return fmt.Errorf(".ValidationContext.TrustChainVerification: %v != %v", a.TrustChainVerification, b.TrustChainVerification)
	}
	return nil
}
func (recv *TlsCertificate) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"certificate_chain": nil, "private_key": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TlsCertificate JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		CertificateChain DataSource `json:"certificate_chain,omitempty"`
		PrivateKey       DataSource `json:"private_key,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TlsCertificate" + err.Error())
	}
	recv.CertificateChain = anon.CertificateChain
	recv.PrivateKey = anon.PrivateKey
	return nil
}
func (a TlsCertificate) Compare(b TlsCertificate) error {
	if err := a.CertificateChain.Compare(b.CertificateChain); err != nil {
		return errors.New(".TlsCertificate" + err.Error())
	}
	if err := a.PrivateKey.Compare(b.PrivateKey); err != nil {
		return errors.New(".TlsCertificate" + err.Error())
	}
	return nil
}
func (recv *CommonTLSContext) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"tls_params": nil, "alpn_protocols": nil, "tls_certificate_sds_secret_configs": nil, "tls_certificates": nil, "validation_context": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".CommonTLSContext JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		TLSParams                      TLSParams                       `json:"tls_params,omitempty"`
		AlpnProtocols                  []string                        `json:"alpn_protocols,omitempty"`
		TLSCertificateSdsSecretConfigs []TLSCertificateSdsSecretConfig `json:"tls_certificate_sds_secret_configs,omitempty" nocompare`
		TlsCertificates                []TlsCertificate                `json:"tls_certificates,omitempty"`
		ValidationContext              ValidationContext               `json:"validation_context,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".CommonTLSContext" + err.Error())
	}
	recv.TLSParams = anon.TLSParams
	recv.AlpnProtocols = anon.AlpnProtocols
	recv.TLSCertificateSdsSecretConfigs = anon.TLSCertificateSdsSecretConfigs
	recv.TlsCertificates = anon.TlsCertificates
	recv.ValidationContext = anon.ValidationContext
	return nil
}
func (a CommonTLSContext) Compare(b CommonTLSContext) error {
	if err := a.TLSParams.Compare(b.TLSParams); err != nil {
		return errors.New(".CommonTLSContext" + err.Error())
	}
	if len(a.AlpnProtocols) != len(b.AlpnProtocols) {
		return errors.New(".CommonTLSContext.AlpnProtocols mismatching lengths")
	}
	for i := range a.AlpnProtocols {
		if a.AlpnProtocols[i] != b.AlpnProtocols[i] {
			return fmt.Errorf(".CommonTLSContext.AlpnProtocols: %v != %v", a.AlpnProtocols, b.AlpnProtocols)
		}
	}
	if len(a.TlsCertificates) != len(b.TlsCertificates) {
		return errors.New(".CommonTLSContext.TlsCertificates mismatching lengths")
	}
	for i := range a.TlsCertificates {
		if err := a.TlsCertificates[i].Compare(b.TlsCertificates[i]); err != nil {
			return errors.New(".CommonTLSContext" + err.Error())
		}
	}
	if err := a.ValidationContext.Compare(b.ValidationContext); err != nil {
		return errors.New(".CommonTLSContext" + err.Error())
	}
	return nil
}
func (recv *DownstreamTlsContext) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "require_client_certificate": nil, "common_tls_context": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".DownstreamTlsContext JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type                     string           `json:"@type,omitempty" nocompare`
		RequireClientCertificate bool             `json:"require_client_certificate,omitempty"`
		CommonTLSContext         CommonTLSContext `json:"common_tls_context,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".DownstreamTlsContext" + err.Error())
	}
	recv.Type = anon.Type
	recv.RequireClientCertificate = anon.RequireClientCertificate
	recv.CommonTLSContext = anon.CommonTLSContext
	return nil
}
func (a DownstreamTlsContext) Compare(b DownstreamTlsContext) error {
	if a.RequireClientCertificate != b.RequireClientCertificate {
		return fmt.Errorf(".DownstreamTlsContext.RequireClientCertificate: %v != %v", a.RequireClientCertificate, b.RequireClientCertificate)
	}
	if err := a.CommonTLSContext.Compare(b.CommonTLSContext); err != nil {
		return errors.New(".DownstreamTlsContext" + err.Error())
	}
	return nil
}
func (recv *TransportSocket) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "typed_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TransportSocket JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name        string               `json:"name,omitempty"`
		TypedConfig DownstreamTlsContext `json:"typed_config,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TransportSocket" + err.Error())
	}
	recv.Name = anon.Name
	recv.TypedConfig = anon.TypedConfig
	return nil
}
func (a TransportSocket) Compare(b TransportSocket) error {
	if a.Name != b.Name {
		return fmt.Errorf(".TransportSocket.Name: %v != %v", a.Name, b.Name)
	}
	if err := a.TypedConfig.Compare(b.TypedConfig); err != nil {
		return errors.New(".TransportSocket" + err.Error())
	}
	return nil
}
func (recv *FilterChain) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "transport_socket": nil, "filters": nil, "filter_chain_match": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".FilterChain JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name             string           `json:"name,omitempty" nocompare`
		TransportSocket  *TransportSocket `json:"transport_socket,omitempty"`
		Filters          []Filters        `json:"filters,omitempty"`
		FilterChainMatch FilterChainMatch `json:"filter_chain_match,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".FilterChain" + err.Error())
	}
	recv.Name = anon.Name
	recv.TransportSocket = anon.TransportSocket
	recv.Filters = anon.Filters
	recv.FilterChainMatch = anon.FilterChainMatch
	return nil
}
func (a FilterChain) Compare(b FilterChain) error {
	if a.TransportSocket == nil && b.TransportSocket == nil {
	} else if a.TransportSocket != nil && b.TransportSocket != nil {
		if err := (*a.TransportSocket).Compare(*b.TransportSocket); err != nil {
			return errors.New(".FilterChain" + err.Error())
		}
	} else {
		return errors.New(".FilterChain.TransportSocket is nil on one object and not nil on the other")
	}
	if len(a.Filters) != len(b.Filters) {
		return errors.New(".FilterChain.Filters mismatching lengths")
	}
	for i := range a.Filters {
		if err := a.Filters[i].Compare(b.Filters[i]); err != nil {
			return errors.New(".FilterChain" + err.Error())
		}
	}
	if err := a.FilterChainMatch.Compare(b.FilterChainMatch); err != nil {
		return errors.New(".FilterChain" + err.Error())
	}
	return nil
}
func (recv *Cidr) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"address_prefix": nil, "prefix_len": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Cidr JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		AddressPrefix string `json:"address_prefix,omitempty"`
		PrefixLen     uint32 `json:"prefix_len,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Cidr" + err.Error())
	}
	recv.AddressPrefix = anon.AddressPrefix
	recv.PrefixLen = anon.PrefixLen
	return nil
}
func (a Cidr) Compare(b Cidr) error {
	if a.AddressPrefix != b.AddressPrefix {
		return fmt.Errorf(".Cidr.AddressPrefix: %v != %v", a.AddressPrefix, b.AddressPrefix)
	}
	if a.PrefixLen != b.PrefixLen {
		return fmt.Errorf(".Cidr.PrefixLen: %v != %v", a.PrefixLen, b.PrefixLen)
	}
	return nil
}
func (recv *ListenerFilterTypedConfigValue) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"allow_cidrs": nil, "deny_cidrs": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ListenerFilterTypedConfigValue JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		AllowCidrs []Cidr `json:"allow_cidrs,omitempty"`
		DenyCidrs  []Cidr `json:"deny_cidrs,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ListenerFilterTypedConfigValue" + err.Error())
	}
	recv.AllowCidrs = anon.AllowCidrs
	recv.DenyCidrs = anon.DenyCidrs
	return nil
}
func (a ListenerFilterTypedConfigValue) Compare(b ListenerFilterTypedConfigValue) error {
	if len(a.AllowCidrs) != len(b.AllowCidrs) {
		return errors.New(".ListenerFilterTypedConfigValue.AllowCidrs mismatching lengths")
	}
	for i := range a.AllowCidrs {
		if err := a.AllowCidrs[i].Compare(b.AllowCidrs[i]); err != nil {
			return errors.New(".ListenerFilterTypedConfigValue" + err.Error())
		}
	}
	if len(a.DenyCidrs) != len(b.DenyCidrs) {
		return errors.New(".ListenerFilterTypedConfigValue.DenyCidrs mismatching lengths")
	}
	for i := range a.DenyCidrs {
		if err := a.DenyCidrs[i].Compare(b.DenyCidrs[i]); err != nil {
			return errors.New(".ListenerFilterTypedConfigValue" + err.Error())
		}
	}
	return nil
}
func (recv *ListenerFilterTypedConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "type_url": nil, "value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ListenerFilterTypedConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type    string                         `json:"@type,omitempty"`
		TypeURL string                         `json:"type_url,omitempty"`
		Value   ListenerFilterTypedConfigValue `json:"value,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ListenerFilterTypedConfig" + err.Error())
	}
	recv.Type = anon.Type
	recv.TypeURL = anon.TypeURL
	recv.Value = anon.Value
	return nil
}
func (a ListenerFilterTypedConfig) Compare(b ListenerFilterTypedConfig) error {
	if a.Type != b.Type {
		return fmt.Errorf(".ListenerFilterTypedConfig.Type: %v != %v", a.Type, b.Type)
	}
	if a.TypeURL != b.TypeURL {
		return fmt.Errorf(".ListenerFilterTypedConfig.TypeURL: %v != %v", a.TypeURL, b.TypeURL)
	}
	if err := a.Value.Compare(b.Value); err != nil {
		return errors.New(".ListenerFilterTypedConfig" + err.Error())
	}
	return nil
}
func (recv *ListenerFilter) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "typed_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ListenerFilter JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name        string                    `json:"name,omitempty"`
		TypedConfig ListenerFilterTypedConfig `json:"typed_config,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ListenerFilter" + err.Error())
	}
	recv.Name = anon.Name
	recv.TypedConfig = anon.TypedConfig
	return nil
}
func (a ListenerFilter) Compare(b ListenerFilter) error {
	if a.Name != b.Name {
		return fmt.Errorf(".ListenerFilter.Name: %v != %v", a.Name, b.Name)
	}
	if err := a.TypedConfig.Compare(b.TypedConfig); err != nil {
		return errors.New(".ListenerFilter" + err.Error())
	}
	return nil
}
func (recv *SocketOption) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"description": nil, "level": nil, "name": nil, "int_value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".SocketOption JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Description string `json:"description,omitempty"`
		Level       string `json:"level,omitempty"`
		Name        string `json:"name,omitempty"`
		IntValue    string `json:"int_value,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".SocketOption" + err.Error())
	}
	recv.Description = anon.Description
	recv.Level = anon.Level
	recv.Name = anon.Name
	recv.IntValue = anon.IntValue
	return nil
}
func (a SocketOption) Compare(b SocketOption) error {
	if a.Description != b.Description {
		return fmt.Errorf(".SocketOption.Description: %v != %v", a.Description, b.Description)
	}
	if a.Level != b.Level {
		return fmt.Errorf(".SocketOption.Level: %v != %v", a.Level, b.Level)
	}
	if a.Name != b.Name {
		return fmt.Errorf(".SocketOption.Name: %v != %v", a.Name, b.Name)
	}
	if a.IntValue != b.IntValue {
		return fmt.Errorf(".SocketOption.IntValue: %v != %v", a.IntValue, b.IntValue)
	}
	return nil
}
func (recv *Listener) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "name": nil, "address": nil, "reuse_port": nil, "listener_filters": nil, "socket_options": nil, "filter_chains": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Listener JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type            string           `json:"@type,omitempty" nocompare`
		Name            string           `json:"name,omitempty" nocompare`
		Address         Address          `json:"address,omitempty"`
		ReusePort       bool             `json:"reuse_port,omitempty"`
		ListenerFilters []ListenerFilter `json:"listener_filters,omitempty"`
		SocketOptions   []SocketOption   `json:"socket_options,omitempty"`
		FilterChains    []FilterChain    `json:"filter_chains,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Listener" + err.Error())
	}
	recv.Type = anon.Type
	recv.Name = anon.Name
	recv.Address = anon.Address
	recv.ReusePort = anon.ReusePort
	recv.ListenerFilters = anon.ListenerFilters
	recv.SocketOptions = anon.SocketOptions
	recv.FilterChains = anon.FilterChains
	return nil
}
func (a Listener) Compare(b Listener) error {
	if err := a.Address.Compare(b.Address); err != nil {
		return errors.New(".Listener" + err.Error())
	}
	if a.ReusePort != b.ReusePort {
		return fmt.Errorf(".Listener.ReusePort: %v != %v", a.ReusePort, b.ReusePort)
	}
	if len(a.ListenerFilters) != len(b.ListenerFilters) {
		return errors.New(".Listener.ListenerFilters mismatching lengths")
	}
	for i := range a.ListenerFilters {
		if err := a.ListenerFilters[i].Compare(b.ListenerFilters[i]); err != nil {
			return errors.New(".Listener" + err.Error())
		}
	}
	if len(a.SocketOptions) != len(b.SocketOptions) {
		return errors.New(".Listener.SocketOptions mismatching lengths")
	}
	for i := range a.SocketOptions {
		if err := a.SocketOptions[i].Compare(b.SocketOptions[i]); err != nil {
			return errors.New(".Listener" + err.Error())
		}
	}
	if len(a.FilterChains) != len(b.FilterChains) {
		return errors.New(".Listener.FilterChains mismatching lengths")
	}
	for i := range a.FilterChains {
		if err := a.FilterChains[i].Compare(b.FilterChains[i]); err != nil {
			return errors.New(".Listener" + err.Error())
		}
	}
	return nil
}
func (recv *Match) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"prefix": nil, "path": nil, "safe_regex": nil, "path_match_policy": nil, "path_separated_prefix": nil, "headers": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Match JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Prefix              string               `json:"prefix,omitempty"`
		Path                string               `json:"path,omitempty"`
		SafeRegex           RegexMatcher         `json:"safe_regex,omitempty"`
		PathMatchPolicy     TypedExtensionConfig `json:"path_match_policy,omitempty"`
		PathSeparatedPrefix string               `json:"path_separated_prefix,omitempty"`
		Headers             []HeaderMatcher      `json:"headers,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Match" + err.Error())
	}
	recv.Prefix = anon.Prefix
	recv.Path = anon.Path
	recv.SafeRegex = anon.SafeRegex
	recv.PathMatchPolicy = anon.PathMatchPolicy
	recv.PathSeparatedPrefix = anon.PathSeparatedPrefix
	recv.Headers = anon.Headers
	return nil
}
func (a Match) Compare(b Match) error {
	if a.Prefix != b.Prefix {
		return fmt.Errorf(".Match.Prefix: %v != %v", a.Prefix, b.Prefix)
	}
	if a.Path != b.Path {
		return fmt.Errorf(".Match.Path: %v != %v", a.Path, b.Path)
	}
	if err := a.SafeRegex.Compare(b.SafeRegex); err != nil {
		return errors.New(".Match" + err.Error())
	}
	if err := a.PathMatchPolicy.Compare(b.PathMatchPolicy); err != nil {
		return errors.New(".Match" + err.Error())
	}
	if a.PathSeparatedPrefix != b.PathSeparatedPrefix {
		return fmt.Errorf(".Match.PathSeparatedPrefix: %v != %v", a.PathSeparatedPrefix, b.PathSeparatedPrefix)
	}
	if len(a.Headers) != len(b.Headers) {
		return errors.New(".Match.Headers mismatching lengths")
	}
	for i := range a.Headers {
		if err := a.Headers[i].Compare(b.Headers[i]); err != nil {
			return errors.New(".Match" + err.Error())
		}
	}
	return nil
}
func (recv *HeaderMatcher) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "exact_match": nil, "range_match": nil, "present_match": nil, "prefix_match": nil, "suffix_match": nil, "contains_match": nil, "invert_match": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HeaderMatcher JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name          string     `json:"name,omitempty"`
		ExactMatch    string     `json:"exact_match,omitempty"`
		RangeMatch    Int64Range `json:"range_match,omitempty"`
		PresentMatch  bool       `json:"present_match,omitempty"`
		PrefixMatch   string     `json:"prefix_match,omitempty"`
		SuffixMatch   string     `json:"suffix_match,omitempty"`
		ContainsMatch string     `json:"contains_match,omitempty"`
		InvertMatch   bool       `json:"invert_match,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HeaderMatcher" + err.Error())
	}
	recv.Name = anon.Name
	recv.ExactMatch = anon.ExactMatch
	recv.RangeMatch = anon.RangeMatch
	recv.PresentMatch = anon.PresentMatch
	recv.PrefixMatch = anon.PrefixMatch
	recv.SuffixMatch = anon.SuffixMatch
	recv.ContainsMatch = anon.ContainsMatch
	recv.InvertMatch = anon.InvertMatch
	return nil
}
func (a HeaderMatcher) Compare(b HeaderMatcher) error {
	if a.Name != b.Name {
		return fmt.Errorf(".HeaderMatcher.Name: %v != %v", a.Name, b.Name)
	}
	if a.ExactMatch != b.ExactMatch {
		return fmt.Errorf(".HeaderMatcher.ExactMatch: %v != %v", a.ExactMatch, b.ExactMatch)
	}
	if err := a.RangeMatch.Compare(b.RangeMatch); err != nil {
		return errors.New(".HeaderMatcher" + err.Error())
	}
	if a.PresentMatch != b.PresentMatch {
		return fmt.Errorf(".HeaderMatcher.PresentMatch: %v != %v", a.PresentMatch, b.PresentMatch)
	}
	if a.PrefixMatch != b.PrefixMatch {
		return fmt.Errorf(".HeaderMatcher.PrefixMatch: %v != %v", a.PrefixMatch, b.PrefixMatch)
	}
	if a.SuffixMatch != b.SuffixMatch {
		return fmt.Errorf(".HeaderMatcher.SuffixMatch: %v != %v", a.SuffixMatch, b.SuffixMatch)
	}
	if a.ContainsMatch != b.ContainsMatch {
		return fmt.Errorf(".HeaderMatcher.ContainsMatch: %v != %v", a.ContainsMatch, b.ContainsMatch)
	}
	if a.InvertMatch != b.InvertMatch {
		return fmt.Errorf(".HeaderMatcher.InvertMatch: %v != %v", a.InvertMatch, b.InvertMatch)
	}
	return nil
}
func (recv *RegexMatcher) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"google_re2": nil, "regex": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".RegexMatcher JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		GoogleRe2 GoogleRE2 `json:"google_re2,omitempty"`
		Regex     string    `json:"regex,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".RegexMatcher" + err.Error())
	}
	recv.GoogleRe2 = anon.GoogleRe2
	recv.Regex = anon.Regex
	return nil
}
func (a RegexMatcher) Compare(b RegexMatcher) error {
	if err := a.GoogleRe2.Compare(b.GoogleRe2); err != nil {
		return errors.New(".RegexMatcher" + err.Error())
	}
	if a.Regex != b.Regex {
		return fmt.Errorf(".RegexMatcher.Regex: %v != %v", a.Regex, b.Regex)
	}
	return nil
}
func (recv *GoogleRE2) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".GoogleRE2 JSON contains unknown key: " + key)
		}
	}
	anon := struct{}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".GoogleRE2" + err.Error())
	}
	return nil
}
func (a GoogleRE2) Compare(b GoogleRE2) error {
	return nil
}
func (recv *TypedExtensionConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "typed_config": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".TypedExtensionConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name        string `json:"name,omitempty"`
		TypedConfig *Any   `json:"typed_config,omitempty" nocompare`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".TypedExtensionConfig" + err.Error())
	}
	recv.Name = anon.Name
	recv.TypedConfig = anon.TypedConfig
	return nil
}
func (a TypedExtensionConfig) Compare(b TypedExtensionConfig) error {
	if a.Name != b.Name {
		return fmt.Errorf(".TypedExtensionConfig.Name: %v != %v", a.Name, b.Name)
	}
	return nil
}
func (recv *Int64Range) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"start": nil, "end": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Int64Range JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Start int64 `json:"start,omitempty"`
		End   int64 `json:"end,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Int64Range" + err.Error())
	}
	recv.Start = anon.Start
	recv.End = anon.End
	return nil
}
func (a Int64Range) Compare(b Int64Range) error {
	if a.Start != b.Start {
		return fmt.Errorf(".Int64Range.Start: %v != %v", a.Start, b.Start)
	}
	if a.End != b.End {
		return fmt.Errorf(".Int64Range.End: %v != %v", a.End, b.End)
	}
	return nil
}
func (recv *UpgradeConfigs) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"upgrade_type": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".UpgradeConfigs JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		UpgradeType string `json:"upgrade_type,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".UpgradeConfigs" + err.Error())
	}
	recv.UpgradeType = anon.UpgradeType
	return nil
}
func (a UpgradeConfigs) Compare(b UpgradeConfigs) error {
	if a.UpgradeType != b.UpgradeType {
		return fmt.Errorf(".UpgradeConfigs.UpgradeType: %v != %v", a.UpgradeType, b.UpgradeType)
	}
	return nil
}
func (recv *HashPolicyHeader) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HashPolicyHeader JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name string `json:"name,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HashPolicyHeader" + err.Error())
	}
	recv.Name = anon.Name
	return nil
}
func (a HashPolicyHeader) Compare(b HashPolicyHeader) error {
	if a.Name != b.Name {
		return fmt.Errorf(".HashPolicyHeader.Name: %v != %v", a.Name, b.Name)
	}
	return nil
}
func (recv *HashPolicyCookie) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "ttl": nil, "path": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HashPolicyCookie JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name string `json:"name,omitempty"`
		TTL  string `json:"ttl,omitempty"`
		Path string `json:"path,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HashPolicyCookie" + err.Error())
	}
	recv.Name = anon.Name
	recv.TTL = anon.TTL
	recv.Path = anon.Path
	return nil
}
func (a HashPolicyCookie) Compare(b HashPolicyCookie) error {
	if a.Name != b.Name {
		return fmt.Errorf(".HashPolicyCookie.Name: %v != %v", a.Name, b.Name)
	}
	if a.TTL != b.TTL {
		return fmt.Errorf(".HashPolicyCookie.TTL: %v != %v", a.TTL, b.TTL)
	}
	if a.Path != b.Path {
		return fmt.Errorf(".HashPolicyCookie.Path: %v != %v", a.Path, b.Path)
	}
	return nil
}
func (recv *HashPolicyConnectionProperties) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"source_ip": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HashPolicyConnectionProperties JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		SourceIp bool `json:"source_ip,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HashPolicyConnectionProperties" + err.Error())
	}
	recv.SourceIp = anon.SourceIp
	return nil
}
func (a HashPolicyConnectionProperties) Compare(b HashPolicyConnectionProperties) error {
	if a.SourceIp != b.SourceIp {
		return fmt.Errorf(".HashPolicyConnectionProperties.SourceIp: %v != %v", a.SourceIp, b.SourceIp)
	}
	return nil
}
func (recv *HashPolicy) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"header": nil, "cookie": nil, "connection_properties": nil, "terminal": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HashPolicy JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Header               HashPolicyHeader               `json:"header,omitempty"`
		Cookie               HashPolicyCookie               `json:"cookie,omitempty"`
		ConnectionProperties HashPolicyConnectionProperties `json:"connection_properties,omitempty"`
		Terminal             bool                           `json:"terminal,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HashPolicy" + err.Error())
	}
	recv.Header = anon.Header
	recv.Cookie = anon.Cookie
	recv.ConnectionProperties = anon.ConnectionProperties
	recv.Terminal = anon.Terminal
	return nil
}
func (a HashPolicy) Compare(b HashPolicy) error {
	if err := a.Header.Compare(b.Header); err != nil {
		return errors.New(".HashPolicy" + err.Error())
	}
	if err := a.Cookie.Compare(b.Cookie); err != nil {
		return errors.New(".HashPolicy" + err.Error())
	}
	if err := a.ConnectionProperties.Compare(b.ConnectionProperties); err != nil {
		return errors.New(".HashPolicy" + err.Error())
	}
	if a.Terminal != b.Terminal {
		return fmt.Errorf(".HashPolicy.Terminal: %v != %v", a.Terminal, b.Terminal)
	}
	return nil
}
func (recv *ClusterWeight) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "weight": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".ClusterWeight JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name   string `json:"name,omitempty" nocompare`
		Weight int    `json:"weight,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".ClusterWeight" + err.Error())
	}
	recv.Name = anon.Name
	recv.Weight = anon.Weight
	return nil
}
func (a ClusterWeight) Compare(b ClusterWeight) error {
	if a.Weight != b.Weight {
		return fmt.Errorf(".ClusterWeight.Weight: %v != %v", a.Weight, b.Weight)
	}
	return nil
}
func (recv *WeightedClusters) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"clusters": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".WeightedClusters JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Clusters []ClusterWeight `json:"clusters,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".WeightedClusters" + err.Error())
	}
	recv.Clusters = anon.Clusters
	return nil
}
func (a WeightedClusters) Compare(b WeightedClusters) error {
	if len(a.Clusters) != len(b.Clusters) {
		return errors.New(".WeightedClusters.Clusters mismatching lengths")
	}
	for i := range a.Clusters {
		if err := a.Clusters[i].Compare(b.Clusters[i]); err != nil {
			return errors.New(".WeightedClusters" + err.Error())
		}
	}
	return nil
}
func (recv *RouteAction) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"cluster": nil, "weighted_clusters": nil, "timeout": nil, "upgrade_configs": nil, "hash_policy": nil, "idle_timeout": nil, "host_rewrite_literal": nil, "prefix_rewrite": nil, "path_rewrite_policy": nil, "retry_policy": nil, "rate_limits": nil, "cors": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".RouteAction JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Cluster            string               `json:"cluster,omitempty" nocompare`
		WeightedClusters   WeightedClusters     `json:"weighted_clusters,omitempty"`
		Timeout            string               `json:"timeout,omitempty"`
		UpgradeConfigs     []UpgradeConfigs     `json:"upgrade_configs,omitempty"`
		HashPolicy         []HashPolicy         `json:"hash_policy,omitempty"`
		IdleTimeout        string               `json:"idle_timeout,omitempty"`
		HostRewriteLiteral string               `json:"host_rewrite_literal,omitempty"`
		PrefixRewrite      string               `json:"prefix_rewrite,omitempty"`
		PathRewritePolicy  TypedExtensionConfig `json:"path_rewrite_policy,omitempty"`
		RetryPolicy        RetryPolicy          `json:"retry_policy,omitempty"`
		RateLimits         []RateLimit          `json:"rate_limits,omitempty"`
		Cors               CorsPolicy           `json:"cors,omitempty" kapcom:"forcecompare"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".RouteAction" + err.Error())
	}
	recv.Cluster = anon.Cluster
	recv.WeightedClusters = anon.WeightedClusters
	recv.Timeout = anon.Timeout
	recv.UpgradeConfigs = anon.UpgradeConfigs
	recv.HashPolicy = anon.HashPolicy
	recv.IdleTimeout = anon.IdleTimeout
	recv.HostRewriteLiteral = anon.HostRewriteLiteral
	recv.PrefixRewrite = anon.PrefixRewrite
	recv.PathRewritePolicy = anon.PathRewritePolicy
	recv.RetryPolicy = anon.RetryPolicy
	recv.RateLimits = anon.RateLimits
	recv.Cors = anon.Cors
	return nil
}
func (a RouteAction) Compare(b RouteAction) error {
	if err := a.WeightedClusters.Compare(b.WeightedClusters); err != nil {
		return errors.New(".RouteAction" + err.Error())
	}
	if a.Timeout != b.Timeout {
		return fmt.Errorf(".RouteAction.Timeout: %v != %v", a.Timeout, b.Timeout)
	}
	if len(a.UpgradeConfigs) != len(b.UpgradeConfigs) {
		return errors.New(".RouteAction.UpgradeConfigs mismatching lengths")
	}
	for i := range a.UpgradeConfigs {
		if err := a.UpgradeConfigs[i].Compare(b.UpgradeConfigs[i]); err != nil {
			return errors.New(".RouteAction" + err.Error())
		}
	}
	if len(a.HashPolicy) != len(b.HashPolicy) {
		return errors.New(".RouteAction.HashPolicy mismatching lengths")
	}
	for i := range a.HashPolicy {
		if err := a.HashPolicy[i].Compare(b.HashPolicy[i]); err != nil {
			return errors.New(".RouteAction" + err.Error())
		}
	}
	if a.IdleTimeout != b.IdleTimeout {
		return fmt.Errorf(".RouteAction.IdleTimeout: %v != %v", a.IdleTimeout, b.IdleTimeout)
	}
	if a.HostRewriteLiteral != b.HostRewriteLiteral {
		return fmt.Errorf(".RouteAction.HostRewriteLiteral: %v != %v", a.HostRewriteLiteral, b.HostRewriteLiteral)
	}
	if a.PrefixRewrite != b.PrefixRewrite {
		return fmt.Errorf(".RouteAction.PrefixRewrite: %v != %v", a.PrefixRewrite, b.PrefixRewrite)
	}
	if err := a.PathRewritePolicy.Compare(b.PathRewritePolicy); err != nil {
		return errors.New(".RouteAction" + err.Error())
	}
	if err := a.RetryPolicy.Compare(b.RetryPolicy); err != nil {
		return errors.New(".RouteAction" + err.Error())
	}
	if len(a.RateLimits) != len(b.RateLimits) {
		return errors.New(".RouteAction.RateLimits mismatching lengths")
	}
	for i := range a.RateLimits {
		if a.RateLimits[i] != b.RateLimits[i] {
			return fmt.Errorf(".RouteAction.RateLimits: %v != %v", a.RateLimits, b.RateLimits)
		}
	}
	if err := a.Cors.Compare(b.Cors); err != nil {
		return errors.New(".RouteAction" + err.Error())
	}
	return nil
}
func (recv *HeaderSize) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"max_bytes": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HeaderSize JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		MaxBytes int `json:"max_bytes,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HeaderSize" + err.Error())
	}
	recv.MaxBytes = anon.MaxBytes
	return nil
}
func (a HeaderSize) Compare(b HeaderSize) error {
	if a.MaxBytes != b.MaxBytes {
		return fmt.Errorf(".HeaderSize.MaxBytes: %v != %v", a.MaxBytes, b.MaxBytes)
	}
	return nil
}
func (recv *HTTPHeaderSizeValue) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"header_size": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPHeaderSizeValue JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		HeaderSize HeaderSize `json:"header_size,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPHeaderSizeValue" + err.Error())
	}
	recv.HeaderSize = anon.HeaderSize
	return nil
}
func (a HTTPHeaderSizeValue) Compare(b HTTPHeaderSizeValue) error {
	if err := a.HeaderSize.Compare(b.HeaderSize); err != nil {
		return errors.New(".HTTPHeaderSizeValue" + err.Error())
	}
	return nil
}
func (recv *EnvoyFiltersHTTPHeaderSize) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".EnvoyFiltersHTTPHeaderSize JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type  string              `json:"@type,omitempty" nocompare`
		Value HTTPHeaderSizeValue `json:"value,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".EnvoyFiltersHTTPHeaderSize" + err.Error())
	}
	recv.Type = anon.Type
	recv.Value = anon.Value
	return nil
}
func (a EnvoyFiltersHTTPHeaderSize) Compare(b EnvoyFiltersHTTPHeaderSize) error {
	if err := a.Value.Compare(b.Value); err != nil {
		return errors.New(".EnvoyFiltersHTTPHeaderSize" + err.Error())
	}
	return nil
}
func (recv *HTTPIpAllowDenyValue) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"allow_cidrs": nil, "deny_cidrs": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HTTPIpAllowDenyValue JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		AllowCidrs []Cidr `json:"allow_cidrs,omitempty"`
		DenyCidrs  []Cidr `json:"deny_cidrs,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HTTPIpAllowDenyValue" + err.Error())
	}
	recv.AllowCidrs = anon.AllowCidrs
	recv.DenyCidrs = anon.DenyCidrs
	return nil
}
func (a HTTPIpAllowDenyValue) Compare(b HTTPIpAllowDenyValue) error {
	if len(a.AllowCidrs) != len(b.AllowCidrs) {
		return errors.New(".HTTPIpAllowDenyValue.AllowCidrs mismatching lengths")
	}
	for i := range a.AllowCidrs {
		if err := a.AllowCidrs[i].Compare(b.AllowCidrs[i]); err != nil {
			return errors.New(".HTTPIpAllowDenyValue" + err.Error())
		}
	}
	if len(a.DenyCidrs) != len(b.DenyCidrs) {
		return errors.New(".HTTPIpAllowDenyValue.DenyCidrs mismatching lengths")
	}
	for i := range a.DenyCidrs {
		if err := a.DenyCidrs[i].Compare(b.DenyCidrs[i]); err != nil {
			return errors.New(".HTTPIpAllowDenyValue" + err.Error())
		}
	}
	return nil
}
func (recv *EnvoyFiltersHTTPIpAllowDeny) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".EnvoyFiltersHTTPIpAllowDeny JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type  string               `json:"@type,omitempty" nocompare`
		Value HTTPIpAllowDenyValue `json:"value,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".EnvoyFiltersHTTPIpAllowDeny" + err.Error())
	}
	recv.Type = anon.Type
	recv.Value = anon.Value
	return nil
}
func (a EnvoyFiltersHTTPIpAllowDeny) Compare(b EnvoyFiltersHTTPIpAllowDeny) error {
	if err := a.Value.Compare(b.Value); err != nil {
		return errors.New(".EnvoyFiltersHTTPIpAllowDeny" + err.Error())
	}
	return nil
}
func (recv *Redirect) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"https_redirect": nil, "host_redirect": nil, "path_redirect": nil, "prefix_rewrite": nil, "response_code": nil, "strip_query": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Redirect JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		HttpsRedirect bool   `json:"https_redirect,omitempty"`
		HostRedirect  string `json:"host_redirect,omitempty"`
		PathRedirect  string `json:"path_redirect,omitempty"`
		PrefixRewrite string `json:"prefix_rewrite,omitempty"`
		ResponseCode  string `json:"response_code,omitempty"`
		StripQuery    bool   `json:"strip_query,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Redirect" + err.Error())
	}
	recv.HttpsRedirect = anon.HttpsRedirect
	recv.HostRedirect = anon.HostRedirect
	recv.PathRedirect = anon.PathRedirect
	recv.PrefixRewrite = anon.PrefixRewrite
	recv.ResponseCode = anon.ResponseCode
	recv.StripQuery = anon.StripQuery
	return nil
}
func (a Redirect) Compare(b Redirect) error {
	if a.HttpsRedirect != b.HttpsRedirect {
		return fmt.Errorf(".Redirect.HttpsRedirect: %v != %v", a.HttpsRedirect, b.HttpsRedirect)
	}
	if a.HostRedirect != b.HostRedirect {
		return fmt.Errorf(".Redirect.HostRedirect: %v != %v", a.HostRedirect, b.HostRedirect)
	}
	if a.PathRedirect != b.PathRedirect {
		return fmt.Errorf(".Redirect.PathRedirect: %v != %v", a.PathRedirect, b.PathRedirect)
	}
	if a.PrefixRewrite != b.PrefixRewrite {
		return fmt.Errorf(".Redirect.PrefixRewrite: %v != %v", a.PrefixRewrite, b.PrefixRewrite)
	}
	if a.ResponseCode != b.ResponseCode {
		return fmt.Errorf(".Redirect.ResponseCode: %v != %v", a.ResponseCode, b.ResponseCode)
	}
	if a.StripQuery != b.StripQuery {
		return fmt.Errorf(".Redirect.StripQuery: %v != %v", a.StripQuery, b.StripQuery)
	}
	return nil
}
func (recv *DirectResponse) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"status": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".DirectResponse JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Status int `json:"status,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".DirectResponse" + err.Error())
	}
	recv.Status = anon.Status
	return nil
}
func (a DirectResponse) Compare(b DirectResponse) error {
	if a.Status != b.Status {
		return fmt.Errorf(".DirectResponse.Status: %v != %v", a.Status, b.Status)
	}
	return nil
}
func (recv *Header) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"key": nil, "value": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Header JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Key   string `json:"key,omitempty"`
		Value string `json:"value,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Header" + err.Error())
	}
	recv.Key = anon.Key
	recv.Value = anon.Value
	return nil
}
func (a Header) Compare(b Header) error {
	if a.Key != b.Key {
		return fmt.Errorf(".Header.Key: %v != %v", a.Key, b.Key)
	}
	if a.Value != b.Value {
		return fmt.Errorf(".Header.Value: %v != %v", a.Value, b.Value)
	}
	return nil
}
func (recv *HeaderValueOption) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"header": nil, "append": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".HeaderValueOption JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Header Header `json:"header,omitempty"`
		Append *bool  `json:"append"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".HeaderValueOption" + err.Error())
	}
	recv.Header = anon.Header
	recv.Append = anon.Append
	return nil
}
func (a HeaderValueOption) Compare(b HeaderValueOption) error {
	if err := a.Header.Compare(b.Header); err != nil {
		return errors.New(".HeaderValueOption" + err.Error())
	}
	if a.Append == nil && b.Append == nil {
	} else if a.Append != nil && b.Append != nil {
		if *a.Append != *b.Append {
			return fmt.Errorf(".HeaderValueOption.Append: %v != %v", a.Append, b.Append)
		}
	} else {
		return errors.New(".HeaderValueOption.Append is nil on one object and not nil on the other")
	}
	return nil
}
func (recv *Route) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "match": nil, "redirect": nil, "direct_response": nil, "route": nil, "typed_per_filter_config": nil, "request_headers_to_add": nil, "request_headers_to_remove": nil, "response_headers_to_add": nil, "response_headers_to_remove": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Route JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name                    string               `json:"name,omitempty" nocompare`
		Match                   Match                `json:"match,omitempty"`
		Redirect                Redirect             `json:"redirect,omitempty"`
		DirectResponse          DirectResponse       `json:"direct_response,omitempty"`
		Route                   RouteAction          `json:"route,omitempty"`
		TypedPerFilterConfig    TypedPerFilterConfig `json:"typed_per_filter_config,omitempty,forcecompare"`
		RequestHeadersToAdd     []HeaderValueOption  `json:"request_headers_to_add,omitempty"`
		RequestHeadersToRemove  []string             `json:"request_headers_to_remove,omitempty"`
		ResponseHeadersToAdd    []HeaderValueOption  `json:"response_headers_to_add,omitempty"`
		ResponseHeadersToRemove []string             `json:"response_headers_to_remove,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Route" + err.Error())
	}
	recv.Name = anon.Name
	recv.Match = anon.Match
	recv.Redirect = anon.Redirect
	recv.DirectResponse = anon.DirectResponse
	recv.Route = anon.Route
	recv.TypedPerFilterConfig = anon.TypedPerFilterConfig
	recv.RequestHeadersToAdd = anon.RequestHeadersToAdd
	recv.RequestHeadersToRemove = anon.RequestHeadersToRemove
	recv.ResponseHeadersToAdd = anon.ResponseHeadersToAdd
	recv.ResponseHeadersToRemove = anon.ResponseHeadersToRemove
	return nil
}
func (a Route) Compare(b Route) error {
	if err := a.Match.Compare(b.Match); err != nil {
		return errors.New(".Route" + err.Error())
	}
	if err := a.Redirect.Compare(b.Redirect); err != nil {
		return errors.New(".Route" + err.Error())
	}
	if err := a.DirectResponse.Compare(b.DirectResponse); err != nil {
		return errors.New(".Route" + err.Error())
	}
	if err := a.Route.Compare(b.Route); err != nil {
		return errors.New(".Route" + err.Error())
	}
	if err := a.TypedPerFilterConfig.Compare(b.TypedPerFilterConfig); err != nil {
		return errors.New(".Route" + err.Error())
	}
	if len(a.RequestHeadersToAdd) != len(b.RequestHeadersToAdd) {
		return errors.New(".Route.RequestHeadersToAdd mismatching lengths")
	}
	for i := range a.RequestHeadersToAdd {
		if err := a.RequestHeadersToAdd[i].Compare(b.RequestHeadersToAdd[i]); err != nil {
			return errors.New(".Route" + err.Error())
		}
	}
	if len(a.RequestHeadersToRemove) != len(b.RequestHeadersToRemove) {
		return errors.New(".Route.RequestHeadersToRemove mismatching lengths")
	}
	for i := range a.RequestHeadersToRemove {
		if a.RequestHeadersToRemove[i] != b.RequestHeadersToRemove[i] {
			return fmt.Errorf(".Route.RequestHeadersToRemove: %v != %v", a.RequestHeadersToRemove, b.RequestHeadersToRemove)
		}
	}
	if len(a.ResponseHeadersToAdd) != len(b.ResponseHeadersToAdd) {
		return errors.New(".Route.ResponseHeadersToAdd mismatching lengths")
	}
	for i := range a.ResponseHeadersToAdd {
		if err := a.ResponseHeadersToAdd[i].Compare(b.ResponseHeadersToAdd[i]); err != nil {
			return errors.New(".Route" + err.Error())
		}
	}
	if len(a.ResponseHeadersToRemove) != len(b.ResponseHeadersToRemove) {
		return errors.New(".Route.ResponseHeadersToRemove mismatching lengths")
	}
	for i := range a.ResponseHeadersToRemove {
		if a.ResponseHeadersToRemove[i] != b.ResponseHeadersToRemove[i] {
			return fmt.Errorf(".Route.ResponseHeadersToRemove: %v != %v", a.ResponseHeadersToRemove, b.ResponseHeadersToRemove)
		}
	}
	return nil
}
func (recv *RetryPolicy) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"retry_on": nil, "num_retries": nil, "host_selection_retry_max_attempts": nil, "per_try_timeout": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".RetryPolicy JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		RetryOn                       string `json:"retry_on,omitempty"`
		NumRetries                    int    `json:"num_retries,omitempty"`
		HostSelectionRetryMaxAttempts string `json:"host_selection_retry_max_attempts,omitempty" nocompare`
		PerTryTimeout                 string `json:"per_try_timeout,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".RetryPolicy" + err.Error())
	}
	recv.RetryOn = anon.RetryOn
	recv.NumRetries = anon.NumRetries
	recv.HostSelectionRetryMaxAttempts = anon.HostSelectionRetryMaxAttempts
	recv.PerTryTimeout = anon.PerTryTimeout
	return nil
}
func (a RetryPolicy) Compare(b RetryPolicy) error {
	if a.RetryOn != b.RetryOn {
		return fmt.Errorf(".RetryPolicy.RetryOn: %v != %v", a.RetryOn, b.RetryOn)
	}
	if a.NumRetries != b.NumRetries {
		return fmt.Errorf(".RetryPolicy.NumRetries: %v != %v", a.NumRetries, b.NumRetries)
	}
	if a.PerTryTimeout != b.PerTryTimeout {
		return fmt.Errorf(".RetryPolicy.PerTryTimeout: %v != %v", a.PerTryTimeout, b.PerTryTimeout)
	}
	return nil
}
func (recv *VirtualHost) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"name": nil, "domains": nil, "routes": nil, "retry_policy": nil, "typed_per_filter_config": nil, "rate_limits": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".VirtualHost JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Name                 string               `json:"name,omitempty" nocompare`
		Domains              []string             `json:"domains,omitempty"`
		Routes               []Route              `json:"routes,omitempty"`
		RetryPolicy          RetryPolicy          `json:"retry_policy,omitempty"`
		TypedPerFilterConfig TypedPerFilterConfig `json:"typed_per_filter_config,omitempty,forcecompare"`
		RateLimits           []RateLimit          `json:"rate_limits,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".VirtualHost" + err.Error())
	}
	recv.Name = anon.Name
	recv.Domains = anon.Domains
	recv.Routes = anon.Routes
	recv.RetryPolicy = anon.RetryPolicy
	recv.TypedPerFilterConfig = anon.TypedPerFilterConfig
	recv.RateLimits = anon.RateLimits
	return nil
}
func (a VirtualHost) Compare(b VirtualHost) error {
	if len(a.Domains) != len(b.Domains) {
		return errors.New(".VirtualHost.Domains mismatching lengths")
	}
	for i := range a.Domains {
		if a.Domains[i] != b.Domains[i] {
			return fmt.Errorf(".VirtualHost.Domains: %v != %v", a.Domains, b.Domains)
		}
	}
	if len(a.Routes) != len(b.Routes) {
		return errors.New(".VirtualHost.Routes mismatching lengths")
	}
	for i := range a.Routes {
		if err := a.Routes[i].Compare(b.Routes[i]); err != nil {
			return errors.New(".VirtualHost" + err.Error())
		}
	}
	if err := a.RetryPolicy.Compare(b.RetryPolicy); err != nil {
		return errors.New(".VirtualHost" + err.Error())
	}
	if err := a.TypedPerFilterConfig.Compare(b.TypedPerFilterConfig); err != nil {
		return errors.New(".VirtualHost" + err.Error())
	}
	if len(a.RateLimits) != len(b.RateLimits) {
		return errors.New(".VirtualHost.RateLimits mismatching lengths")
	}
	for i := range a.RateLimits {
		if a.RateLimits[i] != b.RateLimits[i] {
			return fmt.Errorf(".VirtualHost.RateLimits: %v != %v", a.RateLimits, b.RateLimits)
		}
	}
	return nil
}
func (recv *RouteConfig) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "name": nil, "virtual_hosts": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".RouteConfig JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type         string        `json:"@type,omitempty" nocompare`
		Name         string        `json:"name,omitempty" nocompare`
		VirtualHosts []VirtualHost `json:"virtual_hosts,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".RouteConfig" + err.Error())
	}
	recv.Type = anon.Type
	recv.Name = anon.Name
	recv.VirtualHosts = anon.VirtualHosts
	return nil
}
func (a RouteConfig) Compare(b RouteConfig) error {
	if len(a.VirtualHosts) != len(b.VirtualHosts) {
		return errors.New(".RouteConfig.VirtualHosts mismatching lengths")
	}
	for i := range a.VirtualHosts {
		if err := a.VirtualHosts[i].Compare(b.VirtualHosts[i]); err != nil {
			return errors.New(".RouteConfig" + err.Error())
		}
	}
	return nil
}
func (recv *Secret) UnmarshalJSON(bs []byte) error {
	allFields := make(map[string]interface {
	})
	if err := json.Unmarshal(bs, &allFields); err != nil {
		return err
	}
	definedFields := map[string]interface {
	}{"@type": nil, "name": nil, "tls_certificate": nil}
	for key := range allFields {
		if _, exists := definedFields[key]; !exists {
			return errors.New(".Secret JSON contains unknown key: " + key)
		}
	}
	anon := struct {
		Type           string         `json:"@type,omitempty" nocompare`
		Name           string         `json:"name,omitempty" nocompare`
		TlsCertificate TlsCertificate `json:"tls_certificate,omitempty"`
	}{}
	if err := json.Unmarshal(bs, &anon); err != nil {
		return errors.New(".Secret" + err.Error())
	}
	recv.Type = anon.Type
	recv.Name = anon.Name
	recv.TlsCertificate = anon.TlsCertificate
	return nil
}
func (a Secret) Compare(b Secret) error {
	if err := a.TlsCertificate.Compare(b.TlsCertificate); err != nil {
		return errors.New(".Secret" + err.Error())
	}
	return nil
}
