package constants

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

const (
	ProgramNameUpper = "KAPCOM"
	ProgramNameLower = "kapcom"
	ProgramVersion   = "1.30.2"

	ServerHeader          = "adobe"
	IngressHeader         = "x-adobe-ingress"
	ServiceIdHeader       = "x-service-id"
	HostPortRewriteHeader = "x-rewrite-host-port"
	ProtocolRewriteHeader = "x-rewrite-protocol"
	PathRewriteHeader     = "x-rewrite-path"

	// must match xlate/listeners.json
	TestIngressClass = "public"

	XDSDelimiter     = "/"
	SecretsDelimiter = "/"
	StatsDelimiter   = "_"

	DefaultApiVersion = core.ApiVersion_V3

	DefaultMinTLSVersion = tls.TlsParameters_TLSv1_1
	DefaultMaxTLSVersion = tls.TlsParameters_TLSv1_3

	StatusValid   = "valid"
	StatusInvalid = "invalid"

	DefaultPublicHTTPName  = "public-http"
	DefaultPublicHTTPSName = "public-https"
	DefaultPublicHTTPPort  = 7000
	DefaultPublicHTTPSPort = 7001

	// update docs if changing the value
	InvalidServiceReference = "invalid_service_reference"

	// filters
	DynFwdProxyFilter       = "envoy.filters.http.dynamic_forward_proxy"
	HeaderSizeFilter        = "envoy.filters.http.header_size"
	HealthCheckSimpleFilter = "envoy.filters.http.health_check_simple"
	IpAllowDenyFilter       = "envoy.filters.http.ip_allow_deny"
	// TODO(bcook) is this in `package wellknown` in a future version of go-control-plane?
	HeaderToMetadataFilter = "envoy.filters.http.header_to_metadata"

	// extensions
	HttpProtocolOptionsExtension = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
	UriTemplateMatcherExtension  = "envoy.path.match.uri_template.uri_template_matcher"
	UriTemplateRewriterExtension = "envoy.path.rewrite.uri_template.uri_template_rewriter"

	// clusters
	DynForwardProxyCluster = "envoy.clusters.dynamic_forward_proxy"

	// z primarily for our tests since our envoy_api sorts resources and we
	// name most things test*
	StatsCluster    = "z_envoy_stats"
	StatsListener   = "envoy-stats"
	ExtAuthzCluster = "z_ext_authz"

	// dynamic forward: cluster names
	DynForwardProxyClusterName    = "dynamic_forward_proxy_cluster"
	DynForwardProxyClusterTLSName = "dynamic_forward_proxy_cluster_tls"

	// package certs uses crypto/rsa for now
	MTLSCA = ProgramNameUpper + " CA"

	InternalNonce = "internal"

	RatelimitClass = "ratelimit_services"
	AuthzClass     = "authz_services"

	// some Lua constants, like the scripts that we will run
	LuaRewritePathScript         = "rewrite_path.lua"
	LuaRewritePathScriptContents = `
function envoy_on_request(request_handle)
	request_handle:logInfo("request-rewrite: static-contour-internal-http (): envoy_on_request")
	local headers = request_handle:headers()
	if headers:get("x-rewrite-path") ~= nil then
		request_handle:logInfo("request-rewrite: static-contour-internal-http (): replacing path with ".. headers:get("x-rewrite-path"))
		headers:replace(":path", headers:get("x-rewrite-path"))
	else
		request_handle:logInfo("request-rewrite: static-contour-internal-http (): no replacement for x-path")
	end
end

function envoy_on_response(response_handle)
end
`

	TopologyZoneLabel = "topology.kubernetes.io/zone"
)

var MTLSParams = &tls.TlsParameters{
	TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_3,
	TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
}
