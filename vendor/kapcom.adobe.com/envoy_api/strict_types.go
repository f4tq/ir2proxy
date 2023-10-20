package envoy_api

import (
	"github.com/golang/protobuf/ptypes/any"
)

type (
	//
	// CDS and commmon
	//
	Any        = any.Any
	DataSource struct {
		InlineBytes  string `json:"inline_bytes,omitempty"`
		InlineString string `json:"inline_string,omitempty"`
	}
	SocketAddress struct {
		Address   string `json:"address,omitempty"`
		PortValue int    `json:"port_value,omitempty" nocompare` // shadow Envoy uses different ports
	}
	Address struct {
		SocketAddress SocketAddress `json:"socket_address,omitempty"`
	}
	Endpoint struct {
		Address Address `json:"address,omitempty"`
	}
	LbEndpoint struct {
		Endpoint Endpoint `json:"endpoint,omitempty"`
	}
	Endpoints struct {
		LbEndpoints []LbEndpoint `json:"lb_endpoints,omitempty"`
	}
	LoadAssignment struct {
		ClusterName string      `json:"cluster_name,omitempty" nocompare` // formed differently
		Endpoints   []Endpoints `json:"endpoints,omitempty"`
	}
	APIConfigSource struct {
		APIType      string         `json:"api_type,omitempty"`
		GrpcServices []GrpcServices `json:"grpc_services,omitempty" kapcom:"forcecompare"`
	}
	ADSConfigSource struct{}
	ConfigSource    struct {
		APIConfigSource     APIConfigSource `json:"api_config_source,omitempty"`
		ADSConfigSource     ADSConfigSource `json:"ads,omitempty"`
		InitialFetchTimeout string          `json:"initial_fetch_timeout,omitempty"`
		ResourceApiVersion  string          `json:"resource_api_version,omitempty"`
	}
	EdsClusterConfig struct {
		EdsConfig   ConfigSource `json:"eds_config,omitempty"`
		ServiceName string       `json:"service_name,omitempty"`
	}
	Thresholds struct {
		MaxConnections int `json:"max_connections,omitempty"`
		MaxRequests    int `json:"max_requests,omitempty"`
	}
	CircuitBreakers struct {
		Thresholds []Thresholds `json:"thresholds,omitempty"`
	}
	HealthyPanicThreshold struct {
		Value int `json:"value,omitempty"`
	}
	CommonLbConfig struct {
		HealthyPanicThreshold HealthyPanicThreshold `json:"healthy_panic_threshold,omitempty"`
	}
	HTTP2ProtocolOptions      struct{}
	CommonHTTPProtocolOptions struct {
		IdleTimeout string `json:"idle_timeout,omitempty"`
	}
	ExpectedStatus struct {
		Start string `json:"start,omitempty"`
		End   string `json:"end,omitempty"`
	}
	HTTPHealthCheck struct {
		Host             string           `json:"host,omitempty" nocompare` // kapcom vs contour
		Path             string           `json:"path,omitempty"`
		ExpectedStatuses []ExpectedStatus `json:"expected_statuses,omitempty"`
	}
	HealthCheck struct {
		Timeout               string          `json:"timeout,omitempty"`
		Interval              string          `json:"interval,omitempty"`
		UnhealthyThreshold    int             `json:"unhealthy_threshold,omitempty"`
		HealthyThreshold      int             `json:"healthy_threshold,omitempty"`
		HTTPHealthCheck       HTTPHealthCheck `json:"http_health_check,omitempty"`
		IntervalJitterPercent int             `json:"interval_jitter_percent,omitempty"`
		InitialJitter         string          `json:"initial_jitter,omitempty"`
		ReuseConnection       *bool           `json:"reuse_connection,omitempty"`
	}
	TCPKeepalive struct {
		KeepaliveProbes   int `json:"keepalive_probes,omitempty"`
		KeepaliveTime     int `json:"keepalive_time,omitempty"`
		KeepaliveInterval int `json:"keepalive_interval,omitempty"`
	}
	UpstreamConnectionOptions struct {
		TCPKeepalive TCPKeepalive `json:"tcp_keepalive,omitempty"`
	}
	Cluster struct {
		Type                          string                    `json:"@type,omitempty" nocompare` // v2 vs v3
		ClusterType                   string                    `json:"type,omitempty"`
		Name                          string                    `json:"name,omitempty" nocompare`               // name formed differently
		EdsClusterConfig              EdsClusterConfig          `json:"eds_cluster_config,omitempty" nocompare` // nothing in common with Contour
		UpstreamConnectionOptions     UpstreamConnectionOptions `json:"upstream_connection_options,omitempty"`
		ConnectTimeout                string                    `json:"connect_timeout,omitempty"`
		CircuitBreakers               CircuitBreakers           `json:"circuit_breakers,omitempty"`
		CommonLbConfig                CommonLbConfig            `json:"common_lb_config,omitempty"`
		AltStatName                   string                    `json:"alt_stat_name,omitempty"`
		CommonHTTPProtocolOptions     CommonHTTPProtocolOptions `json:"common_http_protocol_options,omitempty"`
		HTTP2ProtocolOptions          *HTTP2ProtocolOptions     `json:"http2_protocol_options,omitempty"`
		DrainConnectionsOnHostRemoval bool                      `json:"drain_connections_on_host_removal,omitempty" nocompare` // deprecated by v3
		HealthChecks                  []HealthCheck             `json:"health_checks,omitempty"`
		LbPolicy                      string                    `json:"lb_policy,omitempty"`
		TransportSocket               *TransportSocket          `json:"transport_socket,omitempty"`
		LoadAssignment                LoadAssignment            `json:"load_assignment,omitempty"`
		TypedExtensionProtocolOptions map[string]*Any           `json:"typed_extension_protocol_options,omitempty" nocompare`
		IgnoreHealthOnHostRemoval     bool                      `json:"ignore_health_on_host_removal,omitempty" nocompare` // new in v3
	}

	//
	// LDS
	//

	RdsConfigSource struct {
		ConfigSource    ConfigSource `json:"config_source,omitempty"`
		RouteConfigName string       `json:"route_config_name,omitempty"`
	}
	HTTPFilterTypedConfigValue struct {
		// "envoy.config.filter.http.health_check_simple.v2.HealthCheckSimple"
		Path     string  `json:"path,omitempty"`
		MaxBytes float64 `json:"max_bytes,omitempty"`
	}
	HTTPFilterTypedConfig = HcmTypedConfigFactory
	HTTPFilter            struct {
		Name        string                `json:"name,omitempty" nocompare` // wellknown names changed in v3
		TypedConfig HTTPFilterTypedConfig `json:"typed_config,omitempty"`
	}
	HTTPProtocolOptions struct {
		AcceptHTTP10 bool `json:"accept_http_10,omitempty"`
	}
	LogFormat struct {
		JSONFormat JSONFormat `json:"json_format,omitempty"`
	}
	JSONFormat struct {
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
	}
	AccessLogTypedConfig struct {
		Type       string     `json:"@type,omitempty"`
		Path       string     `json:"path,omitempty"`
		JSONFormat JSONFormat `json:"json_format,omitempty"`
		LogFormat  LogFormat  `json:"log_format,omitempty"`
	}
	AccessLog struct {
		Name        string               `json:"name,omitempty"`
		TypedConfig AccessLogTypedConfig `json:"typed_config,omitempty"`
	}
	TracingSampler struct {
		Type  string `json:"type,omitempty"`
		Param int    `json:"param,omitempty"`
	}
	TracingReporter struct {
		LocalAgentHostPort string `json:"localAgentHostPort,omitempty"`
	}
	TracingHeaders struct {
		JaegerDebugHeader        string `json:"jaegerDebugHeader,omitempty"`
		JaegerBaggageHeader      string `json:"jaegerBaggageHeader,omitempty"`
		TraceContextHeaderName   string `json:"TraceContextHeaderName,omitempty"`
		TraceBaggageHeaderPrefix string `json:"traceBaggageHeaderPrefix,omitempty"`
	}
	TracingBaggageRestrictions struct {
		DenyBaggageOnInitializationFailure bool   `json:"denyBaggageOnInitializationFailure,omitempty"`
		HostPort                           string `json:"hostPort,omitempty"`
	}
	TracingLibraryConfig struct {
		PropagationFormat   string                     `json:"propagation_format,omitempty"`
		Sampler             TracingSampler             `json:"sampler,omitempty"`
		Reporter            TracingReporter            `json:"reporter,omitempty"`
		Headers             TracingHeaders             `json:"headers,omitempty"`
		BaggageRestrictions TracingBaggageRestrictions `json:"baggage_restrictions,omitempty"`
		ServiceName         string                     `json:"service_name,omitempty"`
	}
	HTTPTracingConfig struct {
		Config  TracingLibraryConfig `json:"config,omitempty"`
		Library string               `json:"library,omitempty"`
	}
	HTTPTracing struct {
		Config HTTPTracingConfig `json:"config,omitempty"`
		Name   string            `json:"name,omitempty"`
	}
	Tracing struct {
		HTTP HTTPTracing `json:"http,omitempty"`
	}
	FiltersTypedConfig struct {
		Type                string              `json:"@type,omitempty" nocompare`       // v2 vs v3
		StatPrefix          string              `json:"stat_prefix,omitempty" nocompare` // based on listener name which differs
		ServerName          string              `json:"server_name,omitempty" nocompare` // envoy vs adobe
		RdsConfigSource     RdsConfigSource     `json:"rds,omitempty" nocompare`         // nothing in common with Contour
		RouteConfig         RouteConfig         `json:"route_config,omitempty"`
		HTTPFilters         []HTTPFilter        `json:"http_filters,omitempty"`
		HTTPProtocolOptions HTTPProtocolOptions `json:"http_protocol_options,omitempty"`
		// not comparable once we changed tcp proxy filter's access log format
		//
		// also the name is different in v3
		AccessLog           []AccessLog `json:"access_log,omitempty" nocompare`
		Tracing             Tracing     `json:"tracing,omitempty" nocompare` // xDS HTTPConnectionManager vs bootstrap config
		UseRemoteAddress    bool        `json:"use_remote_address,omitempty"`
		GenerateRequestID   bool        `json:"generate_request_id,omitempty"`
		RequestTimeout      string      `json:"request_timeout,omitempty"`
		MaxRequestHeadersKb int         `json:"max_request_headers_kb,omitempty"`
		NormalizePath       bool        `json:"normalize_path,omitempty"`
		MergeSlashes        bool        `json:"merge_slashes,omitempty"`
		IdleTimeout         string      `json:"idle_timeout,omitempty"`
		Cluster             string      `json:"cluster,omitempty" nocompare` // same reason as Cluster.Name
	}
	Filters struct {
		Name        string             `json:"name,omitempty" nocompare` // wellknown names changed in v3
		TypedConfig FiltersTypedConfig `json:"typed_config,omitempty"`
	}
	FilterChainMatch struct {
		ServerNames []string `json:"server_names,omitempty"`
	}
	TLSParams struct {
		TLSMinimumProtocolVersion string   `json:"tls_minimum_protocol_version,omitempty"`
		TLSMaximumProtocolVersion string   `json:"tls_maximum_protocol_version,omitempty"`
		CipherSuites              []string `json:"cipher_suites,omitempty"`
	}
	TLSCertificateSdsSecretConfig struct {
		Name      string       `json:"name,omitempty"`
		SdsConfig ConfigSource `json:"sds_config,omitempty"`
	}
	ValidationContext struct {
		TrustedCA              DataSource `json:"trusted_ca,omitempty"`
		TrustChainVerification string     `json:"trust_chain_verification,omitempty"`
	}
	TlsCertificate struct {
		CertificateChain DataSource `json:"certificate_chain,omitempty"`
		PrivateKey       DataSource `json:"private_key,omitempty"`
	}
	CommonTLSContext struct {
		TLSParams                      TLSParams                       `json:"tls_params,omitempty"`
		AlpnProtocols                  []string                        `json:"alpn_protocols,omitempty"`
		TLSCertificateSdsSecretConfigs []TLSCertificateSdsSecretConfig `json:"tls_certificate_sds_secret_configs,omitempty" nocompare` // nothing in common with Contour
		TlsCertificates                []TlsCertificate                `json:"tls_certificates,omitempty"`
		ValidationContext              ValidationContext               `json:"validation_context,omitempty"`
	}
	DownstreamTlsContext struct {
		Type                     string           `json:"@type,omitempty" nocompare` // v2 vs v3
		RequireClientCertificate bool             `json:"require_client_certificate,omitempty"`
		CommonTLSContext         CommonTLSContext `json:"common_tls_context,omitempty"`
	}
	TransportSocket struct {
		Name        string               `json:"name,omitempty"`
		TypedConfig DownstreamTlsContext `json:"typed_config,omitempty"`
	}
	FilterChain struct {
		Name            string           `json:"name,omitempty" nocompare` // Contour's default FC has no name. We name ours "default"
		TransportSocket *TransportSocket `json:"transport_socket,omitempty"`
		Filters         []Filters        `json:"filters,omitempty"`
		// we put this last since we expect to have different ServerNames and
		// code generation is ordered. in other words: we want to catch issues
		// with the above fields first
		FilterChainMatch FilterChainMatch `json:"filter_chain_match,omitempty"`
	}
	Cidr struct {
		AddressPrefix string `json:"address_prefix,omitempty"`
		// This is Envoy's internal storage type as well
		PrefixLen uint32 `json:"prefix_len,omitempty"`
	}
	ListenerFilterTypedConfigValue struct {
		AllowCidrs []Cidr `json:"allow_cidrs,omitempty"`
		DenyCidrs  []Cidr `json:"deny_cidrs,omitempty"`
	}
	ListenerFilterTypedConfig struct {
		Type    string                         `json:"@type,omitempty"`
		TypeURL string                         `json:"type_url,omitempty"`
		Value   ListenerFilterTypedConfigValue `json:"value,omitempty"`
	}
	ListenerFilter struct {
		Name        string                    `json:"name,omitempty"`
		TypedConfig ListenerFilterTypedConfig `json:"typed_config,omitempty"`
	}
	SocketOption struct {
		Description string `json:"description,omitempty"`
		Level       string `json:"level,omitempty"`
		Name        string `json:"name,omitempty"`
		IntValue    string `json:"int_value,omitempty"`
	}
	Listener struct {
		Type            string           `json:"@type,omitempty" nocompare` // v2 vs v3
		Name            string           `json:"name,omitempty" nocompare`  // ingress class vs ingress_http
		Address         Address          `json:"address,omitempty"`
		ReusePort       bool             `json:"reuse_port,omitempty"`
		ListenerFilters []ListenerFilter `json:"listener_filters,omitempty"`
		SocketOptions   []SocketOption   `json:"socket_options,omitempty"`
		// we put this last since we expect to have different FilterChainMatches
		// and code generation is ordered. in other words: we want to catch
		// issues with the above fields first
		FilterChains []FilterChain `json:"filter_chains,omitempty"`
	}

	//
	// RDS
	//

	Match struct {
		Prefix              string               `json:"prefix,omitempty"`
		Path                string               `json:"path,omitempty"`
		SafeRegex           RegexMatcher         `json:"safe_regex,omitempty"`
		PathMatchPolicy     TypedExtensionConfig `json:"path_match_policy,omitempty"`
		PathSeparatedPrefix string               `json:"path_separated_prefix,omitempty"`
		Headers             []HeaderMatcher      `json:"headers,omitempty"`
	}
	HeaderMatcher struct {
		Name          string     `json:"name,omitempty"`
		ExactMatch    string     `json:"exact_match,omitempty"`
		RangeMatch    Int64Range `json:"range_match,omitempty"`
		PresentMatch  bool       `json:"present_match,omitempty"`
		PrefixMatch   string     `json:"prefix_match,omitempty"`
		SuffixMatch   string     `json:"suffix_match,omitempty"`
		ContainsMatch string     `json:"contains_match,omitempty"`
		InvertMatch   bool       `json:"invert_match,omitempty"`
	}
	RegexMatcher struct {
		GoogleRe2 GoogleRE2 `json:"google_re2,omitempty"`
		Regex     string    `json:"regex,omitempty"`
	}
	GoogleRE2            struct{}
	TypedExtensionConfig struct {
		Name        string `json:"name,omitempty"`
		TypedConfig *Any   `json:"typed_config,omitempty" nocompare`
	}
	Int64Range struct {
		Start int64 `json:"start,omitempty"`
		End   int64 `json:"end,omitempty"`
	}
	UpgradeConfigs struct {
		UpgradeType string `json:"upgrade_type,omitempty"`
	}
	HashPolicyHeader struct {
		Name string `json:"name,omitempty"`
	}
	HashPolicyCookie struct {
		Name string `json:"name,omitempty"`
		TTL  string `json:"ttl,omitempty"`
		Path string `json:"path,omitempty"`
	}
	HashPolicyConnectionProperties struct {
		SourceIp bool `json:"source_ip,omitempty"`
	}
	HashPolicy struct {
		Header               HashPolicyHeader               `json:"header,omitempty"`
		Cookie               HashPolicyCookie               `json:"cookie,omitempty"`
		ConnectionProperties HashPolicyConnectionProperties `json:"connection_properties,omitempty"`
		Terminal             bool                           `json:"terminal,omitempty"`
	}
	ClusterWeight struct {
		Name   string `json:"name,omitempty" nocompare` // same reason as Cluster.Name
		Weight int    `json:"weight,omitempty"`
	}
	WeightedClusters struct {
		Clusters []ClusterWeight `json:"clusters,omitempty"`
	}
	RouteAction struct {
		Cluster            string               `json:"cluster,omitempty" nocompare` // same reason as Cluster.Name
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
	}
	HeaderSize struct {
		MaxBytes int `json:"max_bytes,omitempty"`
	}
	HTTPHeaderSizeValue struct {
		HeaderSize HeaderSize `json:"header_size,omitempty"`
	}
	EnvoyFiltersHTTPHeaderSize struct {
		// type.googleapis.com/google.protobuf.Struct
		// vs
		// type.googleapis.com/udpa.type.v1.TypedStruct
		Type  string              `json:"@type,omitempty" nocompare`
		Value HTTPHeaderSizeValue `json:"value,omitempty"`
	}
	HTTPIpAllowDenyValue struct {
		AllowCidrs []Cidr `json:"allow_cidrs,omitempty"`
		DenyCidrs  []Cidr `json:"deny_cidrs,omitempty"`
	}
	EnvoyFiltersHTTPIpAllowDeny struct {
		// type.googleapis.com/google.protobuf.Struct
		// vs
		// type.googleapis.com/udpa.type.v1.TypedStruct
		Type  string               `json:"@type,omitempty" nocompare`
		Value HTTPIpAllowDenyValue `json:"value,omitempty"`
	}
	TypedPerFilterConfig = TypedPerFilterConfigFactory
	Redirect             struct {
		HttpsRedirect bool   `json:"https_redirect,omitempty"`
		HostRedirect  string `json:"host_redirect,omitempty"`
		PathRedirect  string `json:"path_redirect,omitempty"`
		PrefixRewrite string `json:"prefix_rewrite,omitempty"`
		ResponseCode  string `json:"response_code,omitempty"`
		StripQuery    bool   `json:"strip_query,omitempty"`
	}
	DirectResponse struct {
		Status int `json:"status,omitempty"`
	}
	Header struct {
		Key   string `json:"key,omitempty"`
		Value string `json:"value,omitempty"`
	}
	HeaderValueOption struct {
		Header Header `json:"header,omitempty"`
		Append *bool  `json:"append"` // a ptr because Envoy's default is true
	}
	Route struct {
		Name                    string               `json:"name,omitempty" nocompare` // based on ingress class in KAPCOM
		Match                   Match                `json:"match,omitempty"`
		Redirect                Redirect             `json:"redirect,omitempty"`
		DirectResponse          DirectResponse       `json:"direct_response,omitempty"`
		Route                   RouteAction          `json:"route,omitempty"`
		TypedPerFilterConfig    TypedPerFilterConfig `json:"typed_per_filter_config,omitempty,forcecompare"`
		RequestHeadersToAdd     []HeaderValueOption  `json:"request_headers_to_add,omitempty"`
		RequestHeadersToRemove  []string             `json:"request_headers_to_remove,omitempty"`
		ResponseHeadersToAdd    []HeaderValueOption  `json:"response_headers_to_add,omitempty"`
		ResponseHeadersToRemove []string             `json:"response_headers_to_remove,omitempty"`
	}
	RetryPolicy struct {
		RetryOn                       string `json:"retry_on,omitempty"`
		NumRetries                    int    `json:"num_retries,omitempty"`
		HostSelectionRetryMaxAttempts string `json:"host_selection_retry_max_attempts,omitempty" nocompare` // different in Contour
		PerTryTimeout                 string `json:"per_try_timeout,omitempty"`
	}
	VirtualHost struct {
		Name                 string               `json:"name,omitempty" nocompare` // sometimes hashed in Contour
		Domains              []string             `json:"domains,omitempty"`
		Routes               []Route              `json:"routes,omitempty"`
		RetryPolicy          RetryPolicy          `json:"retry_policy,omitempty"`
		TypedPerFilterConfig TypedPerFilterConfig `json:"typed_per_filter_config,omitempty,forcecompare"`
		RateLimits           []RateLimit          `json:"rate_limits,omitempty"`
	}
	RouteConfig struct {
		Type         string        `json:"@type,omitempty" nocompare` // v2 vs v3
		Name         string        `json:"name,omitempty" nocompare`  // ingress class vs ingress_http
		VirtualHosts []VirtualHost `json:"virtual_hosts,omitempty"`
	}

	//
	// SDS
	//

	Secret struct {
		Type           string         `json:"@type,omitempty" nocompare`
		Name           string         `json:"name,omitempty" nocompare`
		TlsCertificate TlsCertificate `json:"tls_certificate,omitempty"`
	}
)
