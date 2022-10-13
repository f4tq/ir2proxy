package xlate

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"kapcom.adobe.com/ciphers"
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/constants/annotations"
	crds "kapcom.adobe.com/crds/v1"
	"kapcom.adobe.com/set"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xds"

	udpa_type "github.com/cncf/udpa/go/udpa/type/v1"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	trace "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	file_log "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	grpc_log "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	header_to_metadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tls_inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	_struct "github.com/golang/protobuf/ptypes/struct"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/inconshreveable/log15.v2"
	k8s "k8s.io/api/core/v1"
)

type (
	FCbyName []*listener.FilterChain

	FilterChainMeta struct {
		DTC          *tls.DownstreamTlsContext
		TCPProxyFQDN string
	}

	listenerMeta struct {
		ssl       bool
		defaultFC *listener.FilterChain
	}

	hcmOpts uint16

	hcmMutator func(log15.Logger, *hcm.HttpConnectionManager)
)

const (
	optHealthCheck hcmOpts = 1 << iota
	optIPAllowDeny
	optHeaderSize
	optRateLimit
	optGWAuthz
	optCORS
	optGRPCALS
)

var (
	optAll = optHeaderSize | optIPAllowDeny | optHealthCheck
)

// Envoy doesn't accept 0 which means the object's default kicks in
func validPercent(f float64) bool {
	return f > 0 && f <= 100
}

func tlsPassthrough(ingress *Ingress) bool {
	tcpProxy := ingress.Listener.TCPProxy != nil

	passthrough := ingress.Listener.TLS != nil &&
		ingress.Listener.TLS.Passthrough

	return tcpProxy && passthrough
}

func getHCMOpts(ingress *Ingress) (opts hcmOpts) {
	if len(ingress.VirtualHost.RateLimits) > 0 {
		opts |= optRateLimit
	}
	if ingress.VirtualHost.Authorization != nil {
		opts |= optGWAuthz
	}
	if ingress.VirtualHost.Cors != nil {
		opts |= optCORS
	}
	if len(ingress.VirtualHost.Logging.Loggers) > 0 {
		opts |= optGRPCALS
	}
	for _, route := range ingress.VirtualHost.ResolvedRoutes() {
		if pfc := route.PerFilterConfig; pfc != nil {
			if pfc.IpAllowDeny != nil {
				opts |= optIPAllowDeny
			}
			if pfc.HeaderSize != nil {
				opts |= optHeaderSize
			}
			if pfc.Authz != nil {
				opts |= optGWAuthz
			}
		}
		if len(route.RateLimits) > 0 {
			opts |= optRateLimit
		}
		if route.CorsPolicy != nil {
			opts |= optCORS
		}
	}
	return
}

// canBundle is authoritative and evidence of what its decision produces
// are equivalent (not equal) FilterChains
func sniIntersects(fc1, fc2 *listener.FilterChain) (answer bool) {
	if fc1 == nil || fc1.FilterChainMatch == nil ||
		fc2 == nil || fc2.FilterChainMatch == nil {
		return
	}

	for _, sni1 := range fc1.FilterChainMatch.ServerNames {
		for _, sni2 := range fc2.FilterChainMatch.ServerNames {
			if sni1 == sni2 {
				answer = true
				return
			}
		}
	}

	return
}

func sniEqual(fc1, fc2 *listener.FilterChain) (answer bool) {
	if fc1 == nil || fc1.FilterChainMatch == nil ||
		fc2 == nil || fc2.FilterChainMatch == nil {
		return
	}

	if len(fc1.FilterChainMatch.ServerNames) != len(fc2.FilterChainMatch.ServerNames) {
		return
	}

	for i, v := range fc1.FilterChainMatch.ServerNames {
		if fc2.FilterChainMatch.ServerNames[i] != v {
			return
		}
	}

	answer = true
	return
}

func jsonAccessLog(log log15.Logger, http bool) *accesslog.AccessLog {
	var logFields map[string]*_struct.Value
	if http {
		logFields = logFieldsHTTP
	} else {
		logFields = logFieldsTCP
	}

	return &accesslog.AccessLog{
		Name: wellknown.FileAccessLog,
		ConfigType: &accesslog.AccessLog_TypedConfig{
			util.ToAny(log, &file_log.FileAccessLog{
				Path: "/dev/stdout",
				AccessLogFormat: &file_log.FileAccessLog_LogFormat{
					LogFormat: &core.SubstitutionFormatString{
						Format: &core.SubstitutionFormatString_JsonFormat{
							JsonFormat: &_struct.Struct{
								Fields: logFields,
							},
						},
					},
				},
			}),
		},
	}
}

//mExtAuthz - is sidecar only authz
func mExtAuthz(eaz *crds.ExtAuthz) hcmMutator {
	return func(log log15.Logger, hcmConfig *hcm.HttpConnectionManager) {
		if eaz == nil {
			return
		}

		eazFilter := &hcm.HttpFilter{
			Name: wellknown.HTTPExternalAuthorization,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: util.ToAny(log, &ext_authz.ExtAuthz{
					Services: &ext_authz.ExtAuthz_GrpcService{
						GrpcService: &core.GrpcService{
							TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
								EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
									ClusterName: constants.ExtAuthzCluster,
								},
							},
						},
					},
					FailureModeAllow:    eaz.FailureModeAllow,
					TransportApiVersion: core.ApiVersion_V3,
				}),
			},
		}

		hcmConfig.HttpFilters = append(hcmConfig.HttpFilters, eazFilter)
	}
}

func mStatPrefix(statPrefix string) hcmMutator {
	return func(log log15.Logger, hcmConfig *hcm.HttpConnectionManager) {
		if statPrefix != "" {
			hcmConfig.StatPrefix = statPrefix
		}
	}
}

func mStreamIdleTimeout(ic IngressClass) hcmMutator {
	return func(log log15.Logger, hcmConfig *hcm.HttpConnectionManager) {
		if dur := ic.HTTPConnectionManager.StreamIdleTimeout.Duration; dur != 0 {
			hcmConfig.StreamIdleTimeout = ptypes.DurationProto(dur)
		}
	}
}

func mGRPCALS(ingress *Ingress) hcmMutator {
	return func(log log15.Logger, hcmConfig *hcm.HttpConnectionManager) {
		if len(ingress.VirtualHost.Logging.Loggers) == 0 {
			return
		}

		grpcLogger := ingress.VirtualHost.Logging.Loggers[0].GRPC
		if grpcLogger == nil {
			return
		}

		grpcALS := &accesslog.AccessLog{
			Name: wellknown.HTTPGRPCAccessLog,
			ConfigType: &accesslog.AccessLog_TypedConfig{
				TypedConfig: util.ToAny(log, &grpc_log.HttpGrpcAccessLogConfig{
					CommonConfig: &grpc_log.CommonGrpcAccessLogConfig{
						TransportApiVersion: core.ApiVersion_V3,
						LogName:             ingress.Fqdn,
						GrpcService: &core.GrpcService{
							TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
								EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
									ClusterName: GRPCClusterName(grpcLogger),
								},
							},
							Timeout: ptypes.DurationProto(time.Second),
						},
						// TODO(bcook)
						// GrpcStreamRetryPolicy
					},
				}),
			},
		}
		hcmConfig.AccessLog = append(hcmConfig.AccessLog, grpcALS)
	}
}

func mTracing(lc *ListenerConfig, class string) hcmMutator {
	return func(log log15.Logger, hcmConfig *hcm.HttpConnectionManager) {
		cfg := lc.IngressClasses[class].Tracing
		if cfg == nil {
			return
		}

		hcmT := new(hcm.HttpConnectionManager_Tracing)
		hcmConfig.Tracing = hcmT

		if validPercent(cfg.ClientSampling) {
			hcmT.ClientSampling = &envoy_type.Percent{Value: cfg.ClientSampling}
		}

		if validPercent(cfg.RandomSampling) {
			hcmT.RandomSampling = &envoy_type.Percent{Value: cfg.RandomSampling}
		}

		if validPercent(cfg.OverallSampling) {
			hcmT.OverallSampling = &envoy_type.Percent{Value: cfg.OverallSampling}
		}

		if cfg.Verbose != nil {
			hcmT.Verbose = *cfg.Verbose
		}

		sv := func(value string) *_struct.Value {
			return &_struct.Value{
				Kind: &_struct.Value_StringValue{value},
			}
		}
		nv := func(value float64) *_struct.Value {
			return &_struct.Value{
				Kind: &_struct.Value_NumberValue{value},
			}
		}
		bv := func(value bool) *_struct.Value {
			return &_struct.Value{
				Kind: &_struct.Value_BoolValue{value},
			}
		}

		// TODO(bcook) make more of this configurable
		hcmT.Provider = &trace.Tracing_Http{
			Name: "envoy.dynamic.ot",
			ConfigType: &trace.Tracing_Http_TypedConfig{
				TypedConfig: util.ToAny(log, &trace.DynamicOtConfig{
					Library: cfg.LibraryPath,
					Config: &_struct.Struct{
						Fields: map[string]*_struct.Value{
							"service_name":       sv(cfg.ServiceName),
							"propagation_format": sv(cfg.PropagationFormat),
							"sampler": {
								Kind: &_struct.Value_StructValue{
									StructValue: &_struct.Struct{
										Fields: map[string]*_struct.Value{
											"type":  sv("const"), // Sampling happens at the otel collector
											"param": nv(1),
										},
									},
								},
							},
							"reporter": {
								Kind: &_struct.Value_StructValue{
									StructValue: &_struct.Struct{
										Fields: map[string]*_struct.Value{
											"localAgentHostPort": sv("127.0.0.1:6831"),
										},
									},
								},
							},
							"headers": {
								Kind: &_struct.Value_StructValue{
									StructValue: &_struct.Struct{
										Fields: map[string]*_struct.Value{
											"jaegerDebugHeader":        sv("jaeger-debug-id"),
											"jaegerBaggageHeader":      sv("jaeger-baggage"),
											"traceBaggageHeaderPrefix": sv("uberctx-"),
										},
									},
								},
							},
							"baggage_restrictions": {
								Kind: &_struct.Value_StructValue{
									StructValue: &_struct.Struct{
										Fields: map[string]*_struct.Value{
											"denyBaggageOnInitializationFailure": bv(false),
											"hostPort":                           sv(""),
										},
									},
								},
							},
						},
					},
				}),
			},
		}
	}
}

func mMiscFilters(opts hcmOpts, ingresses ...*Ingress) hcmMutator {
	return func(log log15.Logger, hcmConfig *hcm.HttpConnectionManager) {

		httpFilters := []*hcm.HttpFilter{}

		if config.AdobeEnvoyExtensions() {
			if opts&optIPAllowDeny > 0 {
				httpFilters = append(httpFilters, &hcm.HttpFilter{
					Name: "envoy.filters.http.ip_allow_deny",
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: util.ToAny(log, &udpa_type.TypedStruct{
							TypeUrl: "envoy.config.filter.network.ip_allow_deny.v2.IpAllowDeny",
						}),
					},
				})
			}

			if opts&optHealthCheck > 0 {
				httpFilters = append(httpFilters, &hcm.HttpFilter{
					Name: constants.HealthCheckSimpleFilter,
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: util.ToAny(log, &udpa_type.TypedStruct{
							TypeUrl: "envoy.config.filter.http.health_check_simple.v2.HealthCheckSimple",
							Value: &_struct.Struct{
								Fields: map[string]*_struct.Value{
									"path": {Kind: &_struct.Value_StringValue{"/envoy_health_94eaa5a6ba44fc17d1da432d4a1e2d73"}},
								},
							},
						}),
					},
				})
			}

			if opts&optHeaderSize > 0 {
				httpFilters = append(httpFilters, &hcm.HttpFilter{
					Name: constants.HeaderSizeFilter,
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: util.ToAny(log, &udpa_type.TypedStruct{
							TypeUrl: "envoy.config.filter.http.header_size.v2.HeaderSize",
							Value: &_struct.Struct{
								Fields: map[string]*_struct.Value{
									// https://github.com/phylake/envoy/commit/70e6900f46273472bf3932421b01691551df8362
									"max_bytes": {Kind: &_struct.Value_NumberValue{64 * 1024}},
								},
							},
						}),
					},
				})
			}
		}

		if opts&optCORS > 0 {
			a, err := anypb.New(proto.MessageV2(CorsHcmFilter()))
			if err != nil {
				log.Error("Can't convert Cors")
			} else {
				httpFilters = append(httpFilters, &hcm.HttpFilter{
					Name: wellknown.CORS,
					ConfigType: &hcm.HttpFilter_TypedConfig{
						TypedConfig: a,
					},
				})
			}
		}

		if opts&optGWAuthz > 0 {
			filter := AuthzHcmFilter()
			if filter == nil {
				log.Error("authz filter requested but not configured")
			} else {
				a, err := anypb.New(proto.MessageV2(AuthzHcmFilter()))
				if err != nil {
					log.Error("Can't convert Authz filter")
				} else {
					httpFilters = append(httpFilters, &hcm.HttpFilter{
						Name: wellknown.HTTPExternalAuthorization,
						ConfigType: &hcm.HttpFilter_TypedConfig{
							TypedConfig: a,
						},
					})
				}
			}
		}

		if opts&optRateLimit > 0 {
			// Ratelimiting needs context (ingress)
			// add ratelimit to the chain.
			// in practice, ingress is an optional argument
			for _, ingress := range ingresses {
				// pass the target ingress
				anyb, err := anypb.New(proto.MessageV2(RateLimitHcmFilter(ingress)))
				if err != nil {
					config.Log.Error("RateLimitHcmFilter encoding error", "Error", err)

				} else {
					httpFilters = append(httpFilters, &hcm.HttpFilter{
						Name: wellknown.HTTPRateLimit,
						ConfigType: &hcm.HttpFilter_TypedConfig{
							TypedConfig: anyb,
						},
					})
				}
			}
		}

		hcmConfig.HttpFilters = append(hcmConfig.HttpFilters, httpFilters...)
	}
}

func hcmFilter(log log15.Logger, listenerName string,
	mutators ...hcmMutator) *listener.Filter {

	hcmConfig := &hcm.HttpConnectionManager{
		StatPrefix: listenerName,
		ServerName: constants.ServerHeader,
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			&hcm.Rds{
				RouteConfigName: listenerName,
				ConfigSource:    xds.ConfigSource(),
			},
		},
		GenerateRequestId:   &wrappers.BoolValue{Value: false},
		MaxRequestHeadersKb: &wrappers.UInt32Value{Value: 64},
		HttpProtocolOptions: &core.Http1ProtocolOptions{
			AcceptHttp_10: true,
		},
		AccessLog: []*accesslog.AccessLog{
			jsonAccessLog(log, true),
		},
		UseRemoteAddress: &wrappers.BoolValue{Value: true},
		NormalizePath:    &wrappers.BoolValue{Value: true},
		RequestTimeout:   &duration.Duration{}, // disabled
		MergeSlashes:     true,
	}

	for _, mutator := range mutators {
		mutator(log, hcmConfig)
	}

	// ensure envoy.filters.http.header_to_metadata is first so subsequent
	// filters can access metadata
	htmf := &hcm.HttpFilter{
		Name: constants.HeaderToMetadataFilter,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: util.ToAny(log, &header_to_metadata.Config{
				// nothing to configure here we just need it for VirtualHosts
			}),
		},
	}
	hcmConfig.HttpFilters = append([]*hcm.HttpFilter{htmf}, hcmConfig.HttpFilters...)

	// router is always last
	routerFilter := &hcm.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: util.ToAny(log, &router.Router{
				SuppressEnvoyHeaders: true,
			}),
		},
	}
	hcmConfig.HttpFilters = append(hcmConfig.HttpFilters, routerFilter)

	return &listener.Filter{
		Name: wellknown.HTTPConnectionManager,
		ConfigType: &listener.Filter_TypedConfig{
			util.ToAny(log, hcmConfig),
		},
	}
}

func tcpProxyFilter(log log15.Logger, nsCRDs namespaceCRDs,
	ingress *Ingress, listenerName, statPrefix string) *listener.Filter {

	clusterWeights := make([]*tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight, 0)
	var totalWeight uint32

	// dependent on whether or not this is a delegated TCPProxy
	for _, cluster := range ingress.Listener.ResolvedTCPProxy().Clusters {
		var kService *k8s.Service
		var exists bool
		if kService, exists = nsCRDs.services[cluster.Name]; !exists {
			continue
		}

		for _, kServicePort := range kService.Spec.Ports {
			// match only the port declared by the Ingress's Cluster
			// the K8s Service could expose more ports
			if !cluster.MatchServicePort(kServicePort, k8s.ProtocolTCP) {
				continue
			}

			clusterName := ClusterName(&cluster, kService, &kServicePort)
			log.Debug("tcpProxyFilter", "clusterName", clusterName)

			var clusterWeight uint32 = 1
			if cluster.Weight != nil {
				clusterWeight = *cluster.Weight
			}

			clusterWeights = append(clusterWeights, &tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight{
				Name:   clusterName,
				Weight: clusterWeight,
			})
			totalWeight += clusterWeight
		}
	}

	// the Service object may not be synced
	if len(clusterWeights) == 0 {
		log.Debug("clusterWeights==0", "ns", ingress.Namespace, "name", ingress.Name)
		return nil
	}
	if ingress.Listener.TCPProxy != nil && ingress.Listener.TCPProxy.delegationFailed {
		log.Debug("tcp proxy delegation failed", "ns", ingress.Namespace, "name", ingress.Name)
		return nil
	}

	if statPrefix == "" {
		statPrefix = ingress.Namespace + constants.StatsDelimiter + ingress.Name
	}

	tcpProxy := &tcp_proxy.TcpProxy{
		StatPrefix: statPrefix,
		AccessLog: []*accesslog.AccessLog{
			jsonAccessLog(log, false),
		},
		// That's what Contour does
		// https://github.com/projectcontour/contour/blob/v1.5.1/internal/envoy/listener.go#L201
		IdleTimeout: ptypes.DurationProto(9001 * time.Second),
	}

	if len(clusterWeights) == 1 {
		tcpProxy.ClusterSpecifier = &tcp_proxy.TcpProxy_Cluster{
			Cluster: clusterWeights[0].Name,
		}
	} else {
		tcpProxy.ClusterSpecifier = &tcp_proxy.TcpProxy_WeightedClusters{
			WeightedClusters: &tcp_proxy.TcpProxy_WeightedCluster{
				Clusters: clusterWeights,
			},
		}
	}

	return &listener.Filter{
		Name: wellknown.TCPProxy,
		ConfigType: &listener.Filter_TypedConfig{
			util.ToAny(log, tcpProxy),
		},
	}
}

func downstreamTlsContext(tlsMin, tlsMax tls.TlsParameters_TlsProtocol,
	customCiphers []string, secretName string, alpns []string,
	mtls *mTLS) *tls.DownstreamTlsContext {

	cipherSuites := customCiphers
	if len(cipherSuites) == 0 {
		cipherSuites = ciphers.DefaultCipherSuites()
	}

	var (
		sdsConfig                []*tls.SdsSecretConfig
		validationContext        *tls.CommonTlsContext_ValidationContext
		tlsCerts                 []*tls.TlsCertificate
		tlsParams                *tls.TlsParameters
		requireClientCertificate *wrappers.BoolValue
	)

	if mtls == nil {
		sdsConfig = []*tls.SdsSecretConfig{
			{
				Name:      secretName,
				SdsConfig: xds.ConfigSource(),
			},
		}
		tlsParams = &tls.TlsParameters{
			TlsMinimumProtocolVersion: tlsMin,
			TlsMaximumProtocolVersion: tlsMax,
			CipherSuites:              cipherSuites,
		}
	} else {
		requireClientCertificate = &wrappers.BoolValue{Value: true}
		validationContext = mtls.caCerts
		// mTLS does not use SDS because eventual consistency isn't fast enough
		// and because it simplified the implementation by not having to maintain
		// SDS
		tlsCerts = []*tls.TlsCertificate{secretToTlsCert(mtls.serverSecret)}
		tlsParams = constants.MTLSParams
	}

	return &tls.DownstreamTlsContext{
		RequireClientCertificate: requireClientCertificate,
		CommonTlsContext: &tls.CommonTlsContext{
			TlsParams:                      tlsParams,
			TlsCertificateSdsSecretConfigs: sdsConfig,
			TlsCertificates:                tlsCerts,
			AlpnProtocols:                  alpns,
			ValidationContextType:          validationContext,
		},
	}
}

func transportSocket(log log15.Logger,
	DTC *tls.DownstreamTlsContext) *core.TransportSocket {

	return &core.TransportSocket{
		Name: wellknown.TransportSocketTls,
		ConfigType: &core.TransportSocket_TypedConfig{
			util.ToAny(log, DTC),
		},
	}
}

// minTLSVersion returns the minimum TLS protocol version that should be configured
// in the listener; it uses the max of the user-defined value and (in order):
// - the listener-wide min TLS version, if it is configured
// - the hard-coded constant
func minTLSVersion(lc *ListenerConfig, class string, version tls.TlsParameters_TlsProtocol) tls.TlsParameters_TlsProtocol {
	if set, minTLS := TLSProtocolVersion(lc.IngressClasses[class].MinTLSVersion); set && minTLS > version {
		return minTLS
	}
	if constants.DefaultMinTLSVersion > version {
		return constants.DefaultMinTLSVersion
	}
	return version
}

func socketOptions(pi *PortInfo) (opts []*core.SocketOption) {
	const (
		// https://github.com/torvalds/linux/blob/v4.19/arch/ia64/include/uapi/asm/socket.h#L17
		SOL_SOCKET = 1

		// https://github.com/torvalds/linux/blob/v4.19/arch/ia64/include/uapi/asm/socket.h#L29
		SO_KEEPALIVE = 9

		// https://github.com/torvalds/linux/blob/v4.19/arch/ia64/include/uapi/asm/socket.h#L32
		SO_PRIORITY = 12

		// https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/in.h#L37-L38
		IPPROTO_TCP = 6

		// https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/tcp.h#L95-L97
		TCP_KEEPIDLE  = 4
		TCP_KEEPINTVL = 5
		TCP_KEEPCNT   = 6
	)

	opts = make([]*core.SocketOption, 0)

	if pi.SockOpts.SO_PRIORITY != nil {
		opts = append(opts, &core.SocketOption{
			Description: "SO_PRIORITY",
			Level:       SOL_SOCKET,
			Name:        SO_PRIORITY,
			Value:       &core.SocketOption_IntValue{int64(*pi.SockOpts.SO_PRIORITY)},
			State:       core.SocketOption_STATE_PREBIND,
		})
	}

	if pi.SockOpts.TCP_KEEPIDLE != nil || pi.SockOpts.TCP_KEEPINTVL != nil || pi.SockOpts.TCP_KEEPCNT != nil {
		opts = append(opts, &core.SocketOption{
			Description: "SO_KEEPALIVE",
			Level:       SOL_SOCKET,
			Name:        SO_KEEPALIVE,
			Value:       &core.SocketOption_IntValue{1},
			State:       core.SocketOption_STATE_PREBIND,
		})
	}

	if pi.SockOpts.TCP_KEEPIDLE != nil {
		opts = append(opts, &core.SocketOption{
			Description: "TCP_KEEPIDLE",
			Level:       IPPROTO_TCP,
			Name:        TCP_KEEPIDLE,
			Value:       &core.SocketOption_IntValue{int64(*pi.SockOpts.TCP_KEEPIDLE)},
			State:       core.SocketOption_STATE_PREBIND,
		})
	}

	if pi.SockOpts.TCP_KEEPINTVL != nil {
		opts = append(opts, &core.SocketOption{
			Description: "TCP_KEEPINTVL",
			Level:       IPPROTO_TCP,
			Name:        TCP_KEEPINTVL,
			Value:       &core.SocketOption_IntValue{int64(*pi.SockOpts.TCP_KEEPINTVL)},
			State:       core.SocketOption_STATE_PREBIND,
		})
	}

	if pi.SockOpts.TCP_KEEPCNT != nil {
		opts = append(opts, &core.SocketOption{
			Description: "TCP_KEEPCNT",
			Level:       IPPROTO_TCP,
			Name:        TCP_KEEPCNT,
			Value:       &core.SocketOption_IntValue{int64(*pi.SockOpts.TCP_KEEPCNT)},
			State:       core.SocketOption_STATE_PREBIND,
		})
	}

	if len(opts) == 0 {
		opts = nil
	}

	return
}

// hasTCPProxyFilter returns true if the given list contains a tcp_proxy filter
func hasTCPProxyFilter(fc *listener.FilterChain) bool {
	for _, f := range fc.Filters {
		if f.Name == wellknown.TCPProxy {
			return true
		}
	}
	return false
}

// getDownstreamTLSContext retrieves the DownstreamTlsContext from a FilterChain
func getDownstreamTLSContext(log log15.Logger, fc *listener.FilterChain) *tls.DownstreamTlsContext {
	cfg := fc.GetTransportSocket().GetTypedConfig()
	if cfg != nil {
		return util.FromAny(log, cfg).(*tls.DownstreamTlsContext)
	}
	return nil
}

func (recv *CRDHandler) canBundle(i1, i2 *Ingress) (answer bool) {
	if i1 == nil || i2 == nil {
		return
	}

	if i1.Class != i2.Class {
		return
	}

	opt1 := getHCMOpts(i1)
	opt2 := getHCMOpts(i2)

	// rate limit filter has ingress-specific config and can't be bundled with
	// anything else
	if (opt1&optRateLimit) > 0 || (opt2&optRateLimit) > 0 {
		return
	}

	// nothing special about ext_authz except that we don't want to expose other
	// services to potential RVS stability/performance issues
	if opt1&optGWAuthz != opt2&optGWAuthz {
		return
	}

	// additional unique access logger on the HTTPConnectionManager
	if (opt1&optGRPCALS) > 0 || (opt2&optGRPCALS) > 0 {
		return
	}

	l1 := i1.Listener
	l2 := i2.Listener

	if l1.TLS == nil || l2.TLS == nil {
		return
	}

	if l1.TLS.SecretName != l2.TLS.SecretName {
		return
	}

	if l1.TLS.MinProtocolVersion != l2.TLS.MinProtocolVersion {
		return
	}

	if l1.TLS.MaxProtocolVersion != l2.TLS.MaxProtocolVersion {
		return
	}

	if !util.SoSEqual(l1.TLS.CipherSuites, l2.TLS.CipherSuites) {
		return
	}

	if l1.TLS.Passthrough != l2.TLS.Passthrough {
		return
	}

	// while the transport socket may be identical, the filter is different
	if (l1.TCPProxy == nil && l2.TCPProxy != nil) ||
		(l1.TCPProxy != nil && l2.TCPProxy == nil) {
		return
	}

	// while the transport socket may be identical, the filter is different
	if (i1.VirtualHost.Routes == nil && i2.VirtualHost.Routes != nil) ||
		(i1.VirtualHost.Routes != nil && i2.VirtualHost.Routes == nil) {
		return
	}

	// the transport socket will be different
	mtls1 := recv.mTLSForIngress(i1)
	mtls2 := recv.mTLSForIngress(i2)
	if (mtls1 == nil && mtls2 != nil) ||
		(mtls1 != nil && mtls2 == nil) {
		return
	}

	answer = true
	return
}

func (recv *CRDHandler) getGatewayListeners(sotw SotW, ingressClass string) []xds.Wrapper {
	var (
		iface    interface{}
		ic       IngressClass
		exists   bool
		wrappers []xds.Wrapper = make([]xds.Wrapper, 0)
		wrapper  xds.Wrapper
	)

	if ic, exists = recv.lc.IngressClasses[ingressClass]; !exists {
		return nil
	}

	for portName, portInfo := range ic.Ports {

		listenerName := ingressClass + portName

		if iface, exists = sotw.lds[listenerName]; exists {
			wrapper = iface.(xds.Wrapper)
		} else {
			l := &listener.Listener{
				Name: listenerName,
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{
							Protocol: core.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &core.SocketAddress_PortValue{
								PortValue: uint32(portInfo.Port),
							},
						},
					},
				},
				FilterChains:    []*listener.FilterChain{},
				ListenerFilters: []*listener.ListenerFilter{},
				SocketOptions:   socketOptions(&portInfo),
			}

			if portInfo.SockOpts.SO_REUSEPORT != nil {
				l.ReusePort = *portInfo.SockOpts.SO_REUSEPORT
			}

			lmeta := &listenerMeta{
				ssl: portInfo.SSL,
			}

			if config.AdobeEnvoyExtensions() && ipAllowDenyListenerFilter != nil {
				l.ListenerFilters = append(l.ListenerFilters, ipAllowDenyListenerFilter)
			}

			if portInfo.SSL {
				l.ListenerFilters = append(l.ListenerFilters, &listener.ListenerFilter{
					Name: wellknown.TlsInspector,
					ConfigType: &listener.ListenerFilter_TypedConfig{
						TypedConfig: util.ToAny(recv.log, &tls_inspector.TlsInspector{}),
					},
				})

				// Configure a default/catch all filterchain if a DefaultCertificate exists
				// setting "server_names" to a blank string will catch clients that don't send SNI
				// https://www.envoyproxy.io/docs/envoy/v1.13.1/api-v2/api/v2/listener/listener_components.proto#listener-filterchainmatch
				if ic.DefaultCert != "" {
					fc := &listener.FilterChain{
						Name: "default",
						Filters: []*listener.Filter{
							hcmFilter(recv.log, listenerName,
								mMiscFilters(optAll),
								mStreamIdleTimeout(ic),
								mTracing(recv.lc, ingressClass),
							),
						},
					}
					lmeta.defaultFC = fc

					fc.FilterChainMatch = &listener.FilterChainMatch{
						ServerNames: []string{""},
					}

					dtc := downstreamTlsContext(
						minTLSVersion(recv.lc, ingressClass, constants.DefaultMinTLSVersion),
						constants.DefaultMaxTLSVersion,
						[]string{},
						ic.DefaultCert,
						[]string{
							"h2",
							"http/1.1",
						},
						nil,
					)

					fc.TransportSocket = transportSocket(recv.log, dtc)

					l.FilterChains = append(l.FilterChains, fc)
				}
			}

			wrapper = xds.NewWrapper(l, lmeta)
			sotw.lds[listenerName] = wrapper
		}

		wrappers = append(wrappers, wrapper)
	}

	return wrappers
}

func (recv *CRDHandler) removeFilterChainMatch(ingress *Ingress) {

	if ingress.Fqdn == "" {
		return
	}

	sotw := recv.envoySubsets[xds.DefaultEnvoySubset]

	for _, wrapper := range recv.getGatewayListeners(sotw, ingress.Class) {
		wrapper.Write(func(msg proto.Message, meta *interface{}) (protoChanged bool) {
			l := msg.(*listener.Listener)
			lmeta := (*meta).(*listenerMeta)

			if !lmeta.ssl {
				return
			}

			var (
				fc      *listener.FilterChain
				fci     int
				foundFC bool
			)

		filterChainLoop:
			for fci, fc = range l.FilterChains {
				if fc.FilterChainMatch == nil {
					continue
				}

				for i, sn := range fc.FilterChainMatch.ServerNames {
					if sn == ingress.Fqdn {
						recv.log.Warn("removed SNI from FilterChain",
							"listener", l.Name, "fqdn", ingress.Fqdn,
							"ns", ingress.Namespace, "name", ingress.Name,
						)

						foundFC = true
						sns := fc.FilterChainMatch.ServerNames
						sns = append(sns[:i], sns[i+1:]...)
						fc.FilterChainMatch.ServerNames = sns
						break filterChainLoop
					}
				}
			}

			if foundFC && len(fc.FilterChainMatch.ServerNames) == 0 {
				recv.log.Info("cleaned up FilterChain with empty server_names", "listener", l.Name)

				fcs := l.FilterChains
				fcs = append(fcs[:fci], fcs[fci+1:]...)
				l.FilterChains = fcs
			}

			protoChanged = foundFC
			return
		})
	}

	recv.updateSotW(xds.DefaultEnvoySubset, xds.ListenerType, sotw.lds)
}

func (recv *CRDHandler) ingressToFilterChain(ingress *Ingress,
	listenerName string) (fc *listener.FilterChain) {

	fc = &listener.FilterChain{
		Filters: []*listener.Filter{},
	}
	serverNames := []string{}

	if ingress.Listener.TCPProxy == nil {
		var opts hcmOpts

		recv.mapIngresses(func(ingress2 *Ingress) (stop bool) {
			if ingress2.Valid() &&
				!ingress2.Analogous(ingress) &&
				recv.isHighestPriorityIngress(ingress2) &&
				(ingress == ingress2 || recv.canBundle(ingress, ingress2)) {
				serverNames = append(serverNames, ingress2.Fqdn)
				opts |= getHCMOpts(ingress2)
			}
			return
		})
		sort.Strings(serverNames)
		f := hcmFilter(recv.log, listenerName,
			mMiscFilters(opts, ingress),
			mStreamIdleTimeout(recv.lc.IngressClasses[ingress.Class]),
			mTracing(recv.lc, ingress.Class),
			mGRPCALS(ingress),
		)
		fc.Filters = append(fc.Filters, f)
	} else {
		serverNames = append(serverNames, ingress.Fqdn)

		f := tcpProxyFilter(recv.log, recv.getNS(ingress.Namespace), ingress, listenerName, "")
		if f != nil {
			fc.Filters = append(fc.Filters, f)
		}
	}

	if len(fc.Filters) == 0 {
		fc = nil
		return
	}

	if len(serverNames) == 0 {
		fc = nil
		return
	}

	fc.FilterChainMatch = &listener.FilterChainMatch{
		ServerNames: serverNames,
	}

	var alpns []string
	if ingress.Listener.TCPProxy == nil {
		alpns = []string{
			"h2",
			"http/1.1",
		}
	}

	if !tlsPassthrough(ingress) {
		dtc := downstreamTlsContext(
			ingress.Listener.TLS.MinProtocolVersion,
			ingress.Listener.TLS.MaxProtocolVersion,
			ingress.Listener.TLS.CipherSuites,
			ingress.Listener.TLS.SecretName,
			alpns,
			nil,
		)

		fc.TransportSocket = transportSocket(recv.log, dtc)
	}

	return
}

func (recv *CRDHandler) checkStatsListener(lds set.Set, shouldUpdateLDS *bool) {
	if recv.statsListener == nil {
		return
	}
	if _, exists := lds[constants.StatsListener]; exists {
		return
	}
	lds[constants.StatsListener] = recv.statsListener
	*shouldUpdateLDS = true
}

func (recv *CRDHandler) updateGatewayLDS(sotw SotW, ingress, ingressOld *Ingress) {
	shouldUpdateLDS := false

	if !recv.commonUpdateLogic(ingress, ingressOld, recv.removeFilterChainMatch) {
		return
	}

	if ingressOld != nil && !recv.canBundle(ingress, ingressOld) {
		recv.removeFilterChainMatch(ingressOld)
	}

	// as part of LDS-specific update logic (above) we could be handling an
	// invalid Ingress
	if !ingress.Valid() {
		return
	}

	for _, wrapper := range recv.getGatewayListeners(sotw, ingress.Class) {
		wrapper.Write(func(msg proto.Message, meta *interface{}) (protoChanged bool) {
			l := msg.(*listener.Listener)
			lmeta := (*meta).(*listenerMeta)

			if lmeta.ssl {
				if ingress.Listener.TLS == nil {
					return
				}

				var (
					fc      *listener.FilterChain
					fci     int
					foundFC bool
				)

				fcNew := recv.ingressToFilterChain(ingress, l.Name)
				for fci, fc = range l.FilterChains {
					if fc.FilterChainMatch == nil {
						continue
					}

					// as new Ingresses canBundle and activate additional config
					// (typically HTTPConnectionManager filters) the only
					// comparison we care about is that some SNI is common
					// between the current FilterChain and the new one
					if sniIntersects(fc, fcNew) && fc != lmeta.defaultFC {
						foundFC = true
						break
					}
				}

				if fcNew != nil {
					if config.DebugLogs() {
						fcNewJson, _ := json.Marshal(fcNew)
						recv.log.Debug("updateGatewayLDS", "ns", ingress.Namespace, "name", ingress.Name,
							"foundFC", foundFC, "len(l.FilterChains)",
							len(l.FilterChains), "fqdn", ingress.Fqdn, "fcNew", string(fcNewJson))
					}

					if foundFC {
						// for TCPProxy assume the cluster name has changed
						// until we have a better way to detect that it has
						if !sniEqual(fc, fcNew) || hasTCPProxyFilter(fcNew) {
							l.FilterChains[fci] = fcNew
							protoChanged = true
						}
					} else {
						l.FilterChains = append(l.FilterChains, fcNew)
						sort.SliceStable(l.FilterChains, func(i, j int) bool {
							return l.FilterChains[i].FilterChainMatch.ServerNames[0] < l.FilterChains[j].FilterChainMatch.ServerNames[0]
						})
						protoChanged = true
					}

					if protoChanged && config.DebugLogs() {
						lJson, _ := json.Marshal(l)
						recv.log.Debug("updateGatewayLDS",
							"listener_name", l.Name, "listener_json", string(lJson))
					}
				}

			} else if len(l.FilterChains) == 0 {

				protoChanged = true

				l.FilterChains = []*listener.FilterChain{
					{
						Filters: []*listener.Filter{
							hcmFilter(recv.log, l.Name,
								mMiscFilters(optAll),
								mTracing(recv.lc, ingress.Class),
							),
						},
					},
				}
			}

			if protoChanged {
				shouldUpdateLDS = true
			}

			return
		})
	}

	recv.checkStatsListener(sotw.lds, &shouldUpdateLDS)

	if shouldUpdateLDS {
		recv.updateSotW(sotw.subset, xds.ListenerType, sotw.lds)
	}
}

func (recv *CRDHandler) updateSidecarLDS(sotw SotW, ingress *Ingress) {
	var (
		iface           interface{}
		exists          bool
		kService        *k8s.Service
		wrapper         xds.Wrapper
		uniqueListeners set.Set = set.New()
		shouldUpdateLDS bool
	)

	if _, exists = recv.lc.IngressClasses[ingress.Class]; !exists {
		return
	}

	nsCRDs := recv.getNS(ingress.Namespace)

	handleCluster := func(cluster Cluster, isTCPProxy bool) {
		if kService, exists = nsCRDs.services[cluster.Name]; !exists {
			return
		}

		// list of port names/numbers that should use TLS
		var tlsPortsArr []string
		tlsPortsArr = append(tlsPortsArr, strings.Split(kService.Annotations[annotations.H2], ",")...)
		tlsPortsArr = append(tlsPortsArr, strings.Split(kService.Annotations[annotations.TLS], ",")...)
		tlsPorts := arr2map(tlsPortsArr)

		for _, kServicePort := range kService.Spec.Ports {
			// match only the port declared by the Ingress's Cluster
			// the K8s Service could expose more ports
			if !cluster.MatchServicePort(kServicePort, k8s.ProtocolTCP) {
				continue
			}

			// don't include hash of Cluster content in ClusterName because none
			// of it is relevant to a Listener but can cause 2 Listeners to be
			// created with the same port binding
			listenerName := ClusterName(&cluster, kService, &kServicePort, OptNoHash)

			// Routes can contain duplicative Cluster/Port combinations
			//
			// We only need one Listener for each unique combination
			if _, exists = uniqueListeners[listenerName]; exists {
				continue
			}

			statPrefix := AltStatName(kService, &kServicePort)

			var filter *listener.Filter
			if isTCPProxy {
				filter = tcpProxyFilter(recv.log, nsCRDs, ingress, listenerName, statPrefix)
			} else {
				filter = hcmFilter(recv.log, listenerName,
					mStatPrefix(statPrefix),
					mMiscFilters(optHealthCheck),
					mExtAuthz(sotw.sidecar.Spec.Filters.ExtAuthz),
					mTracing(recv.lc, ingress.Class),
					mGRPCALS(ingress),
				)
			}

			l := &listener.Listener{
				Name: listenerName,
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{
							Protocol: core.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &core.SocketAddress_PortValue{
								// the sidecar injection mechanism redirects target/container
								// port traffic to that port times two to avoid port collisions
								// and the need to coordinate port assignments
								PortValue: uint32(kServicePort.TargetPort.IntValue() * 2),
							},
						},
					},
				},
				FilterChains: []*listener.FilterChain{
					{
						Filters: []*listener.Filter{
							filter,
						},
					},
				},
			}

			_, tlsPort := tlsPorts[strconv.FormatInt(int64(kServicePort.Port), 10)]
			_, tlsName := tlsPorts[kServicePort.Name]
			upstreamTls := tlsPort || tlsName

			if mtls := recv.mTLSForIngress(ingress); mtls != nil && !upstreamTls {
				dtc := downstreamTlsContext(
					tls.TlsParameters_TLSv1_1,
					tls.TlsParameters_TLSv1_3,
					[]string{},
					"",             // not used
					[]string{"h2"}, // TODO(bcook) no ALPN and http/1.1 on the UpstreamTlsContext works but idk why
					mtls,
				)

				l.FilterChains[0].TransportSocket = transportSocket(recv.log, dtc)

				l.ListenerFilters = append(l.ListenerFilters, &listener.ListenerFilter{
					Name: wellknown.TlsInspector,
					ConfigType: &listener.ListenerFilter_TypedConfig{
						TypedConfig: util.ToAny(recv.log, &tls_inspector.TlsInspector{}),
					},
				})
			}

			if iface, exists = sotw.lds[listenerName]; exists {
				wrapper = iface.(xds.Wrapper)
				if wrapper.CompareAndReplace(recv.log, l) {
					shouldUpdateLDS = true
				}
			} else {
				wrapper = xds.NewWrapper(l)
				shouldUpdateLDS = true
			}

			uniqueListeners[listenerName] = wrapper
		}
	}

	if ingress.Listener.TCPProxy == nil {
		for _, route := range ingress.VirtualHost.ResolvedRoutes() {
			for _, cluster := range route.Clusters {
				handleCluster(cluster, false)
			}
		}
	} else {
		for _, cluster := range ingress.Listener.ResolvedTCPProxy().Clusters {
			handleCluster(cluster, true)
		}
	}

	recv.checkStatsListener(uniqueListeners, &shouldUpdateLDS)

	// sotw.lds isn't assignable since SotW is stored as a value
	for k := range sotw.lds {
		if _, exists := uniqueListeners[k]; !exists {
			delete(sotw.lds, k)
		}
	}
	for k := range uniqueListeners {
		sotw.lds[k] = uniqueListeners[k]
	}

	if shouldUpdateLDS {
		recv.updateSotW(sotw.subset, xds.ListenerType, sotw.lds)
	}
}

func (recv *CRDHandler) updateLDS(iface, ifaceOld interface{}) {
	var (
		ingresses           []*Ingress
		ingress, ingressOld *Ingress
	)

	switch crd := iface.(type) {

	case *Ingress:
		ingress = crd
		if ifaceOld != nil {
			ingressOld = ifaceOld.(*Ingress)
		}

		ingresses = []*Ingress{ingress}

	case *k8s.Service:
		ingresses = recv.getIngressList(crd.Namespace, crd.Name)

	default:
		recv.log.Error("updateLDS received unknown type",
			"TypeOf", reflect.TypeOf(iface).String())
		return
	}

	for _, ingress := range ingresses {
		for _, sotw := range recv.getSotWs(ingress) {
			switch sotw.role {
			case GatewayRole:
				recv.updateGatewayLDS(sotw, ingress, ingressOld)
			case SidecarRole:
				recv.updateSidecarLDS(sotw, ingress)
			}
		}
	}
}
