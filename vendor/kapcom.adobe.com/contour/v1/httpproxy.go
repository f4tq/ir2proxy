// Copyright © 2019 VMware
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"kapcom.adobe.com/types"
	"kapcom.adobe.com/xlate"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HTTPProxySpec defines the spec of the CRD.
type HTTPProxySpec struct {
	// Virtualhost appears at most once. If it is present, the object is considered
	// to be a "root".
	// +optional
	VirtualHost *VirtualHost `json:"virtualhost,omitempty"`
	// Routes are the ingress routes. If TCPProxy is present, Routes is ignored.
	//  +optional
	Routes []Route `json:"routes,omitempty"`
	// TCPProxy holds TCP proxy information.
	// +optional
	TCPProxy *TCPProxy `json:"tcpproxy,omitempty"`
	// Includes allow for specific routing configuration to be appended to another HTTPProxy in another namespace.
	// +optional
	Includes []Include `json:"includes,omitempty"`
}

// Include describes a set of policies that can be applied to an HTTPProxy in a namespace.
type Include struct {
	// Name of the HTTPProxy
	Name string `json:"name"`
	// Namespace of the HTTPProxy to include. Defaults to the current namespace if not supplied.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// Conditions are a set of routing properties that is applied to an HTTPProxy in a namespace.
	// +optional
	Conditions []IncludeCondition `json:"conditions,omitempty"`
}

// IncludeCondition are policies that are applied to included HTTPProxies.
// One of Prefix or Header must be provided.
type IncludeCondition struct {
	// Prefix defines a prefix match for a request.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Header specifies the header condition to match.
	// +optional
	Header *HeaderCondition `json:"header,omitempty"`
}

// Condition are policies that are applied on top of HTTPProxies.
// One of Prefix, Path, Regex, PathTemplate, PathSeparatedPrefix or Header must be provided.
type Condition struct {
	// Prefix defines a prefix match for a request.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Path defines an exact path match for a request.
	// +optional
	Path string `json:"adobe:path,omitempty"`

	// Regex defines a path regex match for a request.
	// +optional
	Regex string `json:"adobe:pathRegex,omitempty"`

	// PathTemplate defines a template pattern rule for a request.
	// +optional
	PathTemplate string `json:"adobe:pathTemplate,omitempty"`

	// PathSeparatedPrefix defines either an exact path match or a prefix match, followed by /, for a request.
	// +optional
	PathSeparatedPrefix string `json:"adobe:pathSeparatedPrefix,omitempty"`

	// Header specifies the header condition to match.
	// +optional
	Header *HeaderCondition `json:"header,omitempty"`
}

// HeaderCondition specifies the header condition to match.
// Name is required. Only one of Present or Contains must
// be provided.
type HeaderCondition struct {

	// Name is the name of the header to match on. Name is required.
	// Header names are case insensitive.
	Name string `json:"name"`

	// Present is true if the Header is present in the request.
	// +optional
	Present bool `json:"present,omitempty"`

	// Contains is true if the Header containing this string is present
	// in the request.
	// +optional
	Contains string `json:"contains,omitempty"`

	// NotContains is true if the Header containing this string is not present
	// in the request.
	// +optional
	NotContains string `json:"notcontains,omitempty"`

	// Exact is true if the Header containing this string matches exactly
	// in the request.
	// +optional
	Exact string `json:"exact,omitempty"`

	// NotExact is true if the Header containing this string doesn't match exactly
	// in the request.
	// +optional
	NotExact string `json:"notexact,omitempty"`
}

// HeaderMatchCondition - HeaderCondition gets renamed in later contour

type HeaderMatchCondition = HeaderCondition

// AuthorizationServer configures an external server to authenticate
// client requests. The external server must implement the v3 Envoy
// external authorization GRPC protocol (https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto).
type AuthorizationServer struct {
	// ExtensionServiceRef specifies the extension resource that will authorize client requests.
	//
	// +required
	// TODO: for now, there is only the global ExtAuthz (not including sidecar authz which is different)
	//ExtensionServiceRef ExtensionServiceReference `json:"extensionRef"`

	// AuthPolicy sets a default authorization policy for client requests.
	// This policy will be used unless overridden by individual routes.
	//
	// +optional
	AuthPolicy *AuthorizationPolicy `json:"authPolicy,omitempty"`

	// ResponseTimeout configures maximum time to wait for a check response from the authorization server.
	// Timeout durations are expressed in the Go [Duration format](https://godoc.org/time#ParseDuration).
	// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// The string "infinity" is also a valid input and specifies no timeout.
	//
	// +optional
	// +kubebuilder:validation:Pattern=`^(((\d*(\.\d*)?h)|(\d*(\.\d*)?m)|(\d*(\.\d*)?s)|(\d*(\.\d*)?ms)|(\d*(\.\d*)?us)|(\d*(\.\d*)?µs)|(\d*(\.\d*)?ns))+|infinity|infinite)$`
	ResponseTimeout string `json:"responseTimeout,omitempty"`

	// If FailOpen is true, the client request is forwarded to the upstream service
	// even if the authorization server fails to respond. This field should not be
	// set in most cases. It is intended for use only while migrating applications
	// from internal authorization to Contour external authorization.
	//
	// +optional
	FailOpen bool `json:"failOpen,omitempty"`
}

// AuthorizationPolicy modifies how client requests are authenticated.
type AuthorizationPolicy struct {
	// When true, this field disables client request authentication
	// for the scope of the policy.
	//
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// Context is a set of key/value pairs that are sent to the
	// authentication server in the check request. If a context
	// is provided at an enclosing scope, the entries are merged
	// such that the inner scope overrides matching keys from the
	// outer scope.
	//
	// +optional
	Context map[string]string `json:"context,omitempty"`
}

// VirtualHost appears at most once. If it is present, the object is considered
// to be a "root".
type VirtualHost struct {
	// The fully qualified domain name of the root of the ingress tree
	// all leaves of the DAG rooted at this object relate to the fqdn
	Fqdn string `json:"fqdn"`
	// If present describes tls properties. The CNI names that will be matched on
	// are described in fqdn, the tls.secretName secret must contain a
	// matching certificate
	// +optional
	TLS *TLS `json:"tls,omitempty"`
	// This field configures an extension service to perform
	// authorization for this virtual host. Authorization can
	// only be configured on virtual hosts that have TLS enabled.
	// If the TLS configuration requires client certificate
	// validation, the client certificate is always included in the
	// authentication check request.
	//
	// +optional
	Authorization *AuthorizationServer `json:"authorization,omitempty"`
	// Specifies the cross-origin policy to apply to the VirtualHost.
	// +optional
	CORSPolicy *CORSPolicy `json:"corsPolicy,omitempty"`

	// The policy for rate limiting on the virtual host.
	// +optional
	RateLimitPolicy *RateLimitPolicy `json:"rateLimitPolicy,omitempty"`

	Logging xlate.Logging `json:"adobe:logging,omitempty"`
}

// TLS describes tls properties. The CNI names that will be matched on
// are described in fqdn, the tls.secretName secret must contain a
// matching certificate unless tls.passthrough is set to true.
type TLS struct {
	// required, the name of a secret in the current namespace
	SecretName string `json:"secretName,omitempty"`
	// Minimum TLS version this vhost should negotiate
	// +optional
	MinimumProtocolVersion string `json:"minimumProtocolVersion,omitempty"`
	// Maximum TLS version this vhost should negotiate
	MaximumProtocolVersion string `json:"adobe:maximumProtocolVersion,omitempty"`
	// If Passthrough is set to true, the SecretName will be ignored
	// and the encrypted handshake will be passed through to the
	// backing cluster.
	// +optional
	Passthrough bool `json:"passthrough,omitempty"`
	// Optional list of ciphers to configure in the listener
	CipherSuites []string `json:"adobe:cipherSuites,omitempty"`
}

// CORSHeaderValue specifies the value of the string headers returned by a cross-domain request.
// +kubebuilder:validation:Pattern="^[a-zA-Z0-9!#$%&'*+.^_`|~-]+$"
type CORSHeaderValue string

// CORSPolicy allows setting the CORS policy
type CORSPolicy struct {
	// Specifies whether the resource allows credentials.
	//  +optional
	AllowCredentials bool `json:"allowCredentials,omitempty"`
	// AllowOrigin specifies the origins that will be allowed to do CORS requests. "*" means
	// allow any origin.
	// +kubebuilder:validation:Required
	AllowOrigin []string `json:"allowOrigin"`
	// AllowMethods specifies the content for the *access-control-allow-methods* header.
	// +kubebuilder:validation:Required
	AllowMethods []CORSHeaderValue `json:"allowMethods"`
	// AllowHeaders specifies the content for the *access-control-allow-headers* header.
	//  +optional
	AllowHeaders []CORSHeaderValue `json:"allowHeaders,omitempty"`
	// ExposeHeaders Specifies the content for the *access-control-expose-headers* header.
	//  +optional
	ExposeHeaders []CORSHeaderValue `json:"exposeHeaders,omitempty"`
	// MaxAge indicates for how long the results of a preflight request can be cached.
	// MaxAge durations are expressed in the Go [Duration format](https://godoc.org/time#ParseDuration).
	// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// Only positive values are allowed while 0 disables the cache requiring a preflight OPTIONS
	// check for all cross-origin requests.
	//  +optional
	MaxAge string `json:"maxAge,omitempty"`
}

// Allows to configure percentage of traces
type Tracing struct {
	// target percentage of  requests that will be
	// force traced if the x-client-trace-id
	// header is set.
	ClientSampling uint32 `json:"clientSampling,omitempty"`
	// Target percentage of requests that will be
	// randomly selected for trace generation,
	// if not requested by the client or not forced.
	RandomSampling uint32 `json:"randomSampling,omitempty"`
}

// Route contains the set of routes for a virtual host.
type Route struct {
	// Tracing allows to configure percentage of
	// traces that Envoy will generate for service.
	Tracing *Tracing `json:"adobe:tracing,omitempty"`
	// Conditions are a set of routing properties that is applied to an HTTPProxy in a namespace.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`
	// Services are the services to proxy traffic.
	Services []Service `json:"services,omitempty"`
	// Enables websocket support for the route.
	// +optional
	EnableWebsockets bool `json:"enableWebsockets,omitempty"`
	// AuthPolicy updates the authorization policy that was set
	// on the root HTTPProxy object for client requests that
	// match this route.
	// +optional
	AuthPolicy *AuthorizationPolicy `json:"authPolicy,omitempty"`
	// Allow this path to respond to insecure requests over HTTP which are normally
	// not permitted when a `virtualhost.tls` block is present.
	// +optional
	PermitInsecure bool `json:"permitInsecure,omitempty"`
	// The timeout policy for this route.
	// +optional
	TimeoutPolicy *TimeoutPolicy `json:"timeoutPolicy,omitempty"`
	// The retry policy for this route.
	// +optional
	RetryPolicy *RetryPolicy `json:"retryPolicy,omitempty"`
	// The health check policy for this route.
	// +optional
	HealthCheckPolicy *HTTPHealthCheckPolicy `json:"healthCheckPolicy,omitempty"`
	// The load balancing policy for this route.
	// +optional
	LoadBalancerPolicy *LoadBalancerPolicy `json:"loadBalancerPolicy,omitempty"`
	//Least request load balancing config
	// +optional
	LeastRequestLbConfig *LeastRequestLbConfig `json:"adobe:leastRequestLbConfig,omitempty"`
	//'Cookie' load balancing policy with ttl,path
	// +optional
	CookieLbConfig *CookieLbConfig `json:"adobe:cookieLbConfig,omitempty"`
	// The policy for rewriting the path of the request URL
	// after the request has been routed to a Service.
	//
	// +optional
	PathRewritePolicy *PathRewritePolicy `json:"pathRewritePolicy,omitempty"`

	PerFilterConfig *xlate.PerFilterConfig `json:"adobe:perFilterConfig,omitempty"`

	// The policy for managing request headers during proxying.
	// +optional
	RequestHeadersPolicy *HeadersPolicy `json:"requestHeadersPolicy,omitempty"`
	// The policy for managing response headers during proxying.
	// Rewriting the 'Host' header is not supported.
	// +optional
	ResponseHeadersPolicy *HeadersPolicy `json:"responseHeadersPolicy,omitempty"`

	// Redirect instead of proxy to a service
	Redirect *xlate.Redirect `json:"adobe:redirect,omitempty"`
	// The policy for rate limiting on the route.
	// +optional
	RateLimitPolicy *RateLimitPolicy `json:"rateLimitPolicy,omitempty"`

	// DirectResponsePolicy returns an arbitrary HTTP response directly.
	// +optional
	DirectResponsePolicy *HTTPDirectResponsePolicy `json:"directResponsePolicy,omitempty"`
}

type HTTPDirectResponsePolicy struct {
	// StatusCode is the HTTP response status to be returned.
	// +required
	// +kubebuilder:validation:Minimum=200
	// +kubebuilder:validation:Maximum=599
	StatusCode uint32 `json:"statusCode"`

	// Body is the content of the response body.
	// If this setting is omitted, no body is included in the generated response.
	//
	// Note: Body is not recommended to set too long
	// otherwise it can have significant resource usage impacts.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	//Body string `json:"body,omitempty"`
}

// RateLimitPolicy defines rate limiting parameters.
type RateLimitPolicy struct {
	// Local defines local rate limiting parameters, i.e. parameters
	// for rate limiting that occurs within each Envoy pod as requests
	// are handled.
	// +optional TODO
	// Local *LocalRateLimitPolicy `json:"local,omitempty"`

	// Global defines global rate limiting parameters, i.e. parameters
	// defining descriptors that are sent to an external rate limit
	// service (RLS) for a rate limit decision on each request.
	// +optional
	Global *GlobalRateLimitPolicy `json:"global,omitempty"`
}

// GlobalRateLimitPolicy defines global rate limiting parameters.
type GlobalRateLimitPolicy struct {
	// Descriptors defines the list of descriptors that will
	// be generated and sent to the rate limit service. Each
	// descriptor contains 1+ key-value pair entries.
	// +required
	// +kubebuilder:validation:MinItems=1
	Descriptors []RateLimitDescriptor `json:"descriptors,omitempty"`
}

// RateLimitDescriptor defines a list of key-value pair generators.
type RateLimitDescriptor struct {
	// Entries is the list of key-value pair generators.
	// +required
	// +kubebuilder:validation:MinItems=1
	Entries []RateLimitDescriptorEntry `json:"entries,omitempty"`
}

// RateLimitDescriptorEntry is a key-value pair generator. Exactly
// one field on this struct must be non-nil.
type RateLimitDescriptorEntry struct {
	// GenericKey defines a descriptor entry with a static key and value.
	// +optional
	GenericKey *GenericKeyDescriptor `json:"genericKey,omitempty"`

	// RequestHeader defines a descriptor entry that's populated only if
	// a given header is present on the request. The descriptor key is static,
	// and the descriptor value is equal to the value of the header.
	// +optional
	RequestHeader *RequestHeaderDescriptor `json:"requestHeader,omitempty"`

	// RequestHeaderValueMatch defines a descriptor entry that's populated
	// if the request's headers match a set of 1+ match criteria. The
	// descriptor key is "header_match", and the descriptor value is static.
	// +optional
	RequestHeaderValueMatch *RequestHeaderValueMatchDescriptor `json:"requestHeaderValueMatch,omitempty"`

	// RemoteAddress defines a descriptor entry with a key of "remote_address"
	// and a value equal to the client's IP address (from x-forwarded-for).
	// +optional
	RemoteAddress *RemoteAddressDescriptor `json:"remoteAddress,omitempty"`

	// Metadata defines a descriptor entry that is populated only
	// if the value of metadata_key is found in the dynamic metadata / is of type string
	// Use this descriptor to extract information from dynamic metadata
	// +optional
	Metadata *MetadataDescriptor `json:"adobe:metadata,omitempty"`
}

// GenericKeyDescriptor defines a descriptor entry with a static key and
// value.
type GenericKeyDescriptor struct {
	// Key defines the key of the descriptor entry. If not set, the
	// key is set to "generic_key".
	// +optional
	Key string `json:"key,omitempty"`

	// Value defines the value of the descriptor entry.
	// +required
	// +kubebuilder:validation:MinLength=1
	Value string `json:"value,omitempty"`
}

// RequestHeaderDescriptor defines a descriptor entry that's populated only
// if a given header is present on the request. The value of the descriptor
// entry is equal to the value of the header (if present).
type RequestHeaderDescriptor struct {
	// HeaderName defines the name of the header to look for on the request.
	// +required
	// +kubebuilder:validation:MinLength=1
	HeaderName string `json:"headerName,omitempty"`

	// DescriptorKey defines the key to use on the descriptor entry.
	// +required
	// +kubebuilder:validation:MinLength=1
	DescriptorKey string `json:"descriptorKey,omitempty"`
}

// RequestHeaderValueMatchDescriptor defines a descriptor entry that's populated
// if the request's headers match a set of 1+ match criteria. The descriptor key
// is "header_match", and the descriptor value is statically defined.
type RequestHeaderValueMatchDescriptor struct {
	// Headers is a list of 1+ match criteria to apply against the request
	// to determine whether to populate the descriptor entry or not.
	// +kubebuilder:validation:MinItems=1
	Headers []HeaderMatchCondition `json:"headers,omitempty"`

	// ExpectMatch defines whether the request must positively match the match
	// criteria in order to generate a descriptor entry (i.e. true), or not
	// match the match criteria in order to generate a descriptor entry (i.e. false).
	// The default is true.
	// +kubebuilder:default=true
	ExpectMatch bool `json:"expectMatch,omitempty"`

	// Value defines the value of the descriptor entry.
	// +required
	// +kubebuilder:validation:MinLength=1
	Value string `json:"value,omitempty"`
}

// MetadataDescriptor defines a descriptor entry that's populated only
// if a given header is present on the request. The value of the descriptor
// entry is equal to the value of the metadata_key (if present).
type MetadataDescriptor struct {
	// DescriptorKey defines the key to use for the descriptor entry.
	// +required
	// +kubebuilder:validation:MinLength=1
	DescriptorKey string `json:"descriptorKey,omitempty"`

	// MetadataKey - Metadata struct that defines the key and path to retrieve
	// the string value. A match will only happen if the value
	// in the dynamic metadata is of type string.
	// +required
	MetadataKey *MetadataKey `json:"metadataKey,omitempty"`

	// DefaultValue - An optional value to use if metadata_key is empty.
	// If not set and no value is present under the metadata_key
	// then no descriptor is generated.
	// +optional
	DefaultValue string `json:"defaultValue,omitempty"`
}

// MetadataKey provides a general interface using key and path to retrieve value from Metadata.
// https://www.envoyproxy.io/docs/envoy/latest/api-v3/type/metadata/v3/metadata.proto#envoy-v3-api-msg-type-metadata-v3-metadatakey
type MetadataKey struct {
	// The key name of Metadata to retrieve the Struct from the metadata.
	// Typically, it represents a builtin subsystem or custom extension.
	// +required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key,omitempty"`

	// The path to retrieve the Value from the Struct.
	// It can be a prefix or a full path,
	// e.g. [prop, xyz] for a struct or [prop, foo] for a string in the example, which depends on the particular scenario.
	// +kubebuilder:validation:MinItems=1
	Path []string `json:"path,omitempty"`
}

// RemoteAddressDescriptor defines a descriptor entry with a key of
// "remote_address" and a value equal to the client's IP address
// (from x-forwarded-for).
type RemoteAddressDescriptor struct{}

// TCPProxy contains the set of services to proxy TCP connections.
type TCPProxy struct {
	// The load balancing policy for the backend services.
	// +optional
	LoadBalancerPolicy *LoadBalancerPolicy `json:"loadBalancerPolicy,omitempty"`
	//Least request load balancing config
	// +optional
	LeastRequestLbConfig *LeastRequestLbConfig `json:"adobe:leastRequestLbConfig,omitempty"`

	// Services are the services to proxy traffic
	Services []Service `json:"services,omitempty"`

	// Include specifies that this tcpproxy should be delegated to another HTTPProxy.
	// +optional
	Include *TCPProxyInclude `json:"includes,omitempty"`
}

// TCPProxyInclude describes a target HTTPProxy document which contains the TCPProxy details.
type TCPProxyInclude struct {
	// Name of the child HTTPProxy
	Name string `json:"name"`
	// Namespace of the HTTPProxy to include. Defaults to the current namespace if not supplied.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// Service defines an Kubernetes Service to proxy traffic.
type Service struct {
	// Name is the name of Kubernetes service to proxy traffic.
	// Names defined here will be used to look up corresponding endpoints which contain the ips to route.
	Name string `json:"name"`
	// Port (defined as Integer) to proxy traffic to since a service can have multiple defined.
	Port int `json:"port"`
	// Protocol may be used to specify (or override) the protocol used to reach
	// this Service. Values may be tls, h2, h2c. If omitted, protocol-selection
	// falls back on Service annotations.
	Protocol *string `json:"protocol,omitempty"`
	// Weight defines percentage of traffic to balance traffic
	// +optional
	Weight *uint32 `json:"weight,omitempty"`
	// UpstreamValidation defines how to verify the backend service's certificate
	// +optional
	UpstreamValidation *UpstreamValidation `json:"validation,omitempty"`
	// If Mirror is true the Service will receive a read only mirror of the traffic for this route.
	Mirror bool `json:"mirror,omitempty"`
	// Slow start will gradually increase amount of traffic to a newly added endpoint.
	// +optional
	SlowStartPolicy *SlowStartPolicy `json:"slowStartPolicy,omitempty"`
}

// HTTPHealthCheckPolicy defines health checks on the upstream service.
type HTTPHealthCheckPolicy struct {
	// HTTP endpoint used to perform health checks on upstream service
	Path string `json:"path"`
	// The value of the host header in the HTTP health check request.
	// If left empty (default value), the name "contour-envoy-healthcheck"
	// will be used.
	Host string `json:"host,omitempty"`
	// The interval (seconds) between health checks
	// +optional
	IntervalSeconds int64 `json:"intervalSeconds"`
	// The time to wait (seconds) for a health check response
	// +optional
	TimeoutSeconds int64 `json:"timeoutSeconds"`
	// The number of unhealthy health checks required before a host is marked unhealthy
	// +optional
	UnhealthyThresholdCount uint32 `json:"unhealthyThresholdCount"`
	// The number of healthy health checks required before a host is marked healthy
	// +optional
	HealthyThresholdCount uint32 `json:"healthyThresholdCount"`
}

// TimeoutPolicy defines the attributes associated with timeout.
type TimeoutPolicy struct {
	// Timeout for receiving a response from the server after processing a request from client.
	// If not supplied the timeout duration is undefined.
	Response string `json:"response"`

	// Timeout after which if there are no active requests, the connection between Envoy and the
	// backend will be closed.
	Idle string `json:"idle"`

	// Timeout for how long connection from the proxy to the upstream service is kept when there are no active requests.
	// If not supplied, a cluster default value of 58s applies.
	// +optional
	// +kubebuilder:validation:Pattern=`^(((\d*(\.\d*)?h)|(\d*(\.\d*)?m)|(\d*(\.\d*)?s)|(\d*(\.\d*)?ms)|(\d*(\.\d*)?us)|(\d*(\.\d*)?µs)|(\d*(\.\d*)?ns))+|infinity|infinite)$`
	IdleConnection string `json:"idleConnection,omitempty"`

	Connect string `json:"adobe:connect,omitempty"`
}

// RetryPolicy defines the attributes associated with retrying policy.
type RetryPolicy struct {
	// NumRetries is maximum allowed number of retries.
	// If not supplied, the number of retries is one.
	// +optional
	NumRetries uint32 `json:"count"`
	// PerTryTimeout specifies the timeout per retry attempt.
	// Ignored if NumRetries is not supplied.
	PerTryTimeout string `json:"perTryTimeout,omitempty"`
}

// ReplacePrefix describes a path prefix replacement.
type ReplacePrefix struct {
	// Prefix specifies the URL path prefix to be replaced.
	//
	// If Prefix is specified, it must exactly match the MatchCondition
	// prefix that is rendered by the chain of including HTTPProxies
	// and only that path prefix will be replaced by Replacement.
	// This allows HTTPProxies that are included through multiple
	// roots to only replace specific path prefixes, leaving others
	// unmodified.
	//
	// If Prefix is not specified, all routing prefixes rendered
	// by the include chain will be replaced.
	//
	// +optional
	// +kubebuilder:validation:MinLength=1
	Prefix string `json:"prefix,omitempty"`

	// Replacement is the string that the routing path prefix
	// will be replaced with. This must not be empty.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Replacement string `json:"replacement"`
}

// ReplacePathTemplate describes a path template replacement.
type ReplacePathTemplate struct {
	// Prefix specifies the URL path prefix to be replaced.
	//
	// If Prefix is specified, it must exactly match the MatchCondition
	// path template that is rendered by the chain of including HTTPProxies
	// and only that path template will be replaced by Replacement.
	// This allows HTTPProxies that are included through multiple
	// roots to only replace specific path templates, leaving others
	// unmodified.
	//
	// If Prefix is not specified, all routing path templates rendered
	// by the include chain will be replaced.
	//
	// +optional
	// +kubebuilder:validation:MinLength=1
	Prefix string `json:"prefix,omitempty"`

	// Replacement is the string that the routing path template
	// will be replaced with. This must not be empty.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Replacement string `json:"replacement"`
}

// PathRewritePolicy specifies how a request URL path should be
// rewritten. This rewriting takes place after a request is routed
// and has no subsequent effects on the proxy's routing decision.
// No HTTP headers or body content is rewritten.
//
// Exactly one field in this struct may be specified.
type PathRewritePolicy struct {
	// ReplacePrefix describes how the path prefix should be replaced.
	// +optional
	ReplacePrefix []ReplacePrefix `json:"replacePrefix,omitempty"`
	// ReplacePathTemplate describes how the path template should be replaced.
	// +optional
	ReplacePathTemplate []ReplacePathTemplate `json:"adobe:replacePathTemplate,omitempty"`
}

// HeaderHashOptions contains options to configure a HTTP request header hash
// policy, used in request attribute hash based load balancing.
type HeaderHashOptions struct {
	// HeaderName is the name of the HTTP request header that will be used to
	// calculate the hash key. If the header specified is not present on a
	// request, no hash will be produced.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	HeaderName string `json:"headerName,omitempty"`
}

// QueryParameterHashOptions contains options to configure a query parameter based hash
// policy, used in request attribute hash based load balancing.
type QueryParameterHashOptions struct {
	// ParameterName is the name of the HTTP request query parameter that will be used to
	// calculate the hash key. If the query parameter specified is not present on a
	// request, no hash will be produced.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ParameterName string `json:"parameterName,omitempty"`
}

// RequestHashPolicy contains configuration for an individual hash policy
// on a request attribute.
type RequestHashPolicy struct {
	// Terminal is a flag that allows for short-circuiting computing of a hash
	// for a given request. If set to true, and the request attribute specified
	// in the attribute hash options is present, no further hash policies will
	// be used to calculate a hash for the request.
	Terminal bool `json:"terminal,omitempty"`

	// HeaderHashOptions should be set when request header hash based load
	// balancing is desired. It must be the only hash option field set,
	// otherwise this request hash policy object will be ignored.
	// +kubebuilder:validation:Required
	HeaderHashOptions *HeaderHashOptions `json:"headerHashOptions,omitempty"`

	// QueryParameterHashOptions should be set when request query parameter hash based load
	// balancing is desired. It must be the only hash option field set,
	// otherwise this request hash policy object will be ignored.
	// +optional
	QueryParameterHashOptions *QueryParameterHashOptions `json:"queryParameterHashOptions,omitempty"`

	// HashSourceIP should be set to true when request source IP hash based
	// load balancing is desired. It must be the only hash option field set,
	// otherwise this request hash policy object will be ignored.
	// +optional
	HashSourceIP bool `json:"hashSourceIP,omitempty"`
}

// LoadBalancerPolicy defines the load balancing policy.
type LoadBalancerPolicy struct {
	Strategy string `json:"strategy,omitempty"`
	// RequestHashPolicies contains a list of hash policies to apply when the
	// `RequestHash` load balancing strategy is chosen. If an element of the
	// supplied list of hash policies is invalid, it will be ignored. If the
	// list of hash policies is empty after validation, the load balancing
	// strategy will fall back the the default `RoundRobin`.
	RequestHashPolicies []RequestHashPolicy `json:"requestHashPolicies,omitempty"`
}

type LeastRequestLbConfig struct {
	ChoiceCount uint32 `json:"choiceCount,omitempty"`
}

// CookieLbConfig -- loadbalancer policy similar to upstream Cookie policy except provide ttl,path access
type CookieLbConfig struct {
	Name string          `json:"name"`
	Ttl  *types.Duration `json:"ttl,omitempty"`
	Path string          `json:"path,omitempty"`
	// Override default 'Cookie' Loadbalancing Strategy.
	// By default, 'Cookie' strategy uses RoundRobin.
	Strategy string `json:"strategy,omitempty"`
}

type HeadersPolicy struct {
	// Set specifies a list of HTTP header values that will be set in the HTTP header.
	// If the header does not exist it will be added, otherwise it will be overwritten with the new value.
	// +optional
	Set []HeaderValue `json:"set,omitempty"`
	// Remove specifies a list of HTTP header names to remove.
	// +optional
	Remove []string `json:"remove,omitempty"`
}

// HeaderValue represents a header name/value pair
type HeaderValue struct {
	// Name represents a key of a header
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Value represents the value of a header specified by a key
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Value string `json:"value"`
}

// UpstreamValidation defines how to verify the backend service's certificate
type UpstreamValidation struct {
	// Name of the Kubernetes secret be used to validate the certificate presented by the backend
	CACertificate string `json:"caSecret"`
	// Key which is expected to be present in the 'subjectAltName' of the presented certificate
	SubjectName string `json:"subjectName"`
}

// Status reports the current state of the HTTPProxy.
type Status struct {
	CurrentStatus string `json:"currentStatus"`
	Description   string `json:"description"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HTTPProxy is an Ingress CRD specification
// +k8s:openapi-gen=true
// +kubebuilder:printcolumn:name="FQDN",type="string",JSONPath=".spec.virtualhost.fqdn",description="Fully qualified domain name"
// +kubebuilder:printcolumn:name="TLS Secret",type="string",JSONPath=".spec.virtualhost.tls.secretName",description="Secret with TLS credentials"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.currentStatus",description="The current status of the HTTPProxy"
// +kubebuilder:printcolumn:name="Status Description",type="string",JSONPath=".status.description",description="Description of the current status"
// +kubebuilder:resource:path=httpproxies,shortName=proxy;proxies,singular=httpproxy
type HTTPProxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec HTTPProxySpec `json:"spec"`
	// +optional
	Status `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HTTPProxyList is a list of HTTPProxies.
type HTTPProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []HTTPProxy `json:"items"`
}

// SlowStartPolicy will gradually increase amount of traffic to a newly added endpoint.
// It can be used only with RoundRobin and WeightedLeastRequest load balancing strategies.
type SlowStartPolicy struct {
	// The duration of slow start window.
	// Duration is expressed in the Go [Duration format](https://godoc.org/time#ParseDuration).
	// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// +required
	// +kubebuilder:validation:Pattern=`^(((\d*(\.\d*)?h)|(\d*(\.\d*)?m)|(\d*(\.\d*)?s)|(\d*(\.\d*)?ms)|(\d*(\.\d*)?us)|(\d*(\.\d*)?µs)|(\d*(\.\d*)?ns))+)$`
	Window string `json:"window"`

	// The speed of traffic increase over the slow start window.
	// Defaults to 1.0, so that endpoint would get linearly increasing amount of traffic.
	// When increasing the value for this parameter, the speed of traffic ramp-up increases non-linearly.
	// The value of aggression parameter should be greater than 0.0.
	//
	// More info: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/slow_start
	//
	// +optional
	// +kubebuilder:default=`1.0`
	// +kubebuilder:validation:Pattern=`^([0-9]+([.][0-9]+)?|[.][0-9]+)$`
	Aggression string `json:"aggression"`

	// The minimum or starting percentage of traffic to send to new endpoints.
	// A non-zero value helps avoid a too small initial weight, which may cause endpoints in slow start mode to receive no traffic in the beginning of the slow start window.
	// If not specified, the default is 10%.
	// +optional
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MinimumWeightPercent uint32 `json:"minWeightPercent"`
}
