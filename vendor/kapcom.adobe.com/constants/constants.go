package constants

import (
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

const (
	ProgramNameUpper = "KAPCOM"
	ProgramNameLower = "kapcom"
	ProgramVersion   = "1.20.1"

	ServerHeader    = "adobe"
	IngressHeader   = "x-adobe-ingress"
	ServiceIdHeader = "x-service-id"

	// must match xlate/listeners.json
	TestIngressClass = "public"

	XDSDelimiter     = "/"
	SecretsDelimiter = "/"
	StatsDelimiter   = "_"

	DefaultMinTLSVersion = tls.TlsParameters_TLSv1_1
	DefaultMaxTLSVersion = tls.TlsParameters_TLSv1_3

	StatusValid   = "valid"
	StatusInvalid = "invalid"

	// update docs if changing the value
	InvalidServiceReference = "invalid_service_reference"

	HealthCheckSimpleFilter = "envoy.filters.http.health_check_simple"
	HeaderSizeFilter        = "envoy.filters.http.header_size"
	IpAllowDenyFilter       = "envoy.filters.http.ip_allow_deny"

	// TODO(bcook) is this in `package wellknown` in a future version of go-control-plane?
	HeaderToMetadataFilter = "envoy.filters.http.header_to_metadata"

	// z primarily for our tests since our envoy_api sorts resources and we
	// name most things test*
	StatsCluster    = "z_envoy_stats"
	StatsListener   = "envoy-stats"
	ExtAuthzCluster = "z_ext_authz"

	// package certs uses crypto/rsa for now
	MTLSCA = ProgramNameUpper + " CA"

	InternalNonce = "internal"

	RatelimitClass = "ratelimit_services"
	AuthzClass     = "authz_services"

	TopologyZoneLabel = "topology.kubernetes.io/zone"
)

var (
	MTLSParams = &tls.TlsParameters{
		TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_3,
		TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
	}
)
