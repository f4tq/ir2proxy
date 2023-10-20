package xlate

import (
	"encoding/json"
	"os"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/types"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xds"

	udpa_type "github.com/cncf/udpa/go/udpa/type/v1"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	_struct "github.com/golang/protobuf/ptypes/struct"
	"gopkg.in/inconshreveable/log15.v2"
)

type (
	SocketOptions struct {
		SO_REUSEPORT  *bool   `json:"so_reuseport"`
		SO_PRIORITY   *uint8  `json:"so_priority"`
		TCP_KEEPIDLE  *uint16 `json:"tcp_keepidle"`
		TCP_KEEPINTVL *uint16 `json:"tcp_keepintvl"`
		TCP_KEEPCNT   *uint16 `json:"tcp_keepcnt"`
	}

	PortInfo struct {
		Port     uint16        `json:"port"`
		SSL      bool          `json:"ssl"`
		SockOpts SocketOptions `json:"socket_options"`
	}

	Tracing struct {
		ClientSampling  float64 `json:"client_sampling"`
		RandomSampling  float64 `json:"random_sampling"`
		OverallSampling float64 `json:"overall_sampling"`
		Verbose         *bool   `json:"verbose"`
		ServiceName     string  `json:"service_name,omitempty"`
		TargetUri       string  `json:"target_uri,omitempty"`
	}

	HTTPConnectionManager struct {
		StreamIdleTimeout types.Duration `json:"stream_idle_timeout"`
	}

	IngressClass struct {
		Ports                 map[string]PortInfo   `json:"ports"`
		DefaultCert           string                `json:"default_cert"`
		MinTLSVersion         string                `json:"min_tls_version"`
		Tracing               *Tracing              `json:"tracing"`
		HTTPConnectionManager HTTPConnectionManager `json:"http_connection_manager"`
	}

	Stats struct {
		AdminPort uint16          `json:"admin_port,omitempty"`
		StatsPort uint16          `json:"stats_port,omitempty"`
		Timeout   *types.Duration `json:"timeout"`
	}

	ListenerConfig struct {
		Stats          Stats                   `json:"stats"`
		IngressClasses map[string]IngressClass `json:"ingress_classes"`
	}
)

var (
	logFieldsHTTP             map[string]*_struct.Value
	logFieldsTCP              map[string]*_struct.Value
	ipAllowDenyListenerFilter *listener.ListenerFilter
)

func cidrToProto(cidrs []Cidr, key string, structFields map[string]*_struct.Value) {
	cidrList := &_struct.ListValue{
		Values: make([]*_struct.Value, 0),
	}
	structFields[key] = &_struct.Value{
		Kind: &_struct.Value_ListValue{
			ListValue: cidrList,
		},
	}

	for _, cidr := range cidrs {
		cidrStruct := &_struct.Struct{
			Fields: make(map[string]*_struct.Value),
		}
		cidrStruct.Fields["address_prefix"] = &_struct.Value{
			Kind: &_struct.Value_StringValue{
				StringValue: cidr.AddressPrefix,
			},
		}
		cidrStruct.Fields["prefix_len"] = &_struct.Value{
			Kind: &_struct.Value_NumberValue{
				NumberValue: float64(cidr.PrefixLen),
			},
		}
		cidrList.Values = append(cidrList.Values, &_struct.Value{
			Kind: &_struct.Value_StructValue{
				StructValue: cidrStruct,
			},
		})
	}
}

// https://www.envoyproxy.io/docs/envoy/v1.15.2/configuration/observability/access_log/usage#config-access-log-format-dictionaries
func initLogFields() {
	sv := func(value string) *_struct.Value {
		return &_struct.Value{
			Kind: &_struct.Value_StringValue{value},
		}
	}

	logFieldsHTTP = map[string]*_struct.Value{
		"@timestamp":                sv("%START_TIME%"),
		"authority":                 sv("%REQ(:AUTHORITY)%"),
		"bytes_received":            sv("%BYTES_RECEIVED%"),
		"bytes_sent":                sv("%BYTES_SENT%"),
		"downstream_local_address":  sv("%DOWNSTREAM_LOCAL_ADDRESS%"),
		"downstream_remote_address": sv("%DOWNSTREAM_REMOTE_ADDRESS%"),
		"duration":                  sv("%DURATION%"),
		"method":                    sv("%REQ(:METHOD)%"),
		"path":                      sv("%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"),
		"protocol":                  sv("%PROTOCOL%"),
		"request_duration":          sv("%REQUEST_DURATION%"),
		"request_id":                sv("%REQ(X-REQUEST-ID)%"),
		"requested_server_name":     sv("%REQUESTED_SERVER_NAME%"),
		"response_code_details":     sv("%RESPONSE_CODE_DETAILS%"),
		"response_code":             sv("%RESPONSE_CODE%"),
		"response_duration":         sv("%RESPONSE_DURATION%"),
		"response_flags":            sv("%RESPONSE_FLAGS%"),
		"response_tx_duration":      sv("%RESPONSE_TX_DURATION%"),
		"uber_trace_id":             sv("%REQ(UBER-TRACE-ID)%"),
		"upstream_cluster":          sv("%UPSTREAM_CLUSTER%"),
		"upstream_host":             sv("%UPSTREAM_HOST%"),
		"upstream_local_address":    sv("%UPSTREAM_LOCAL_ADDRESS%"),
		"upstream_service_time":     sv("%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"),
		"user_agent":                sv("%REQ(USER-AGENT)%"),
		"x_forwarded_for":           sv("%REQ(X-FORWARDED-FOR)%"),
	}

	logFieldsTCP = map[string]*_struct.Value{
		"@timestamp":                sv("%START_TIME%"),
		"bytes_received":            sv("%BYTES_RECEIVED%"),
		"bytes_sent":                sv("%BYTES_SENT%"),
		"downstream_local_address":  sv("%DOWNSTREAM_LOCAL_ADDRESS%"),
		"downstream_remote_address": sv("%DOWNSTREAM_REMOTE_ADDRESS%"),
		"duration":                  sv("%DURATION%"),
		"request_duration":          sv("%REQUEST_DURATION%"),
		"requested_server_name":     sv("%REQUESTED_SERVER_NAME%"),
		"response_duration":         sv("%RESPONSE_DURATION%"),
		"response_flags":            sv("%RESPONSE_FLAGS%"),
		"response_tx_duration":      sv("%RESPONSE_TX_DURATION%"),
		"upstream_cluster":          sv("%UPSTREAM_CLUSTER%"),
		"upstream_host":             sv("%UPSTREAM_HOST%"),
		"upstream_local_address":    sv("%UPSTREAM_LOCAL_ADDRESS%"),
	}
}

func init() {
	initLogFields()
}

func LoadIpAllowDenyConfig(log log15.Logger) (success bool) {
	if !config.AdobeEnvoyExtensions() {
		success = true
		return
	}

	path := os.Getenv("CIDR_LIST_PATH")
	if path == "" {
		success = true
		return
	}

	f, err := os.Open(path)
	if err != nil {
		log.Error("CIDR_LIST_PATH was provided but os.Open failed", "Error", err)
		return
	}
	defer f.Close()

	ipConfig := IpAllowDeny{}
	err = json.NewDecoder(f).Decode(&ipConfig)
	if err != nil {
		log.Error("Could not deserialize cidrs in CIDR_LIST_PATH", "Path", path)
		return
	}

	structFields := make(map[string]*_struct.Value)

	if len(ipConfig.AllowCidrs) > 0 {
		cidrToProto(ipConfig.AllowCidrs, "allow_cidrs", structFields)
	}

	if len(ipConfig.DenyCidrs) > 0 {
		cidrToProto(ipConfig.DenyCidrs, "deny_cidrs", structFields)
	}

	if len(structFields) > 0 {
		typedConfig, err := ptypes.MarshalAny(&udpa_type.TypedStruct{
			TypeUrl: "envoy.config.filter.listener.ip_allow_deny.v3.IpAllowDeny",
			Value: &_struct.Struct{
				Fields: structFields,
			},
		})
		if err != nil {
			log.Error("ptypes.MarshalAny", "Error", err)
			return
		}

		ipAllowDenyListenerFilter = new(listener.ListenerFilter)
		ipAllowDenyListenerFilter.Name = "envoy.listener.ip_allow_deny"
		ipAllowDenyListenerFilter.ConfigType = &listener.ListenerFilter_TypedConfig{
			TypedConfig: typedConfig,
		}
	}

	success = true
	return
}

func (recv *CRDHandler) initStatsListener() {
	var timeout *duration.Duration
	if recv.lc.Stats.Timeout != nil {
		timeout = ptypes.DurationProto(recv.lc.Stats.Timeout.Duration)
	}

	recv.statsListener = xds.NewWrapper(&listener.Listener{
		Name: constants.StatsListener,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: uint32(recv.lc.Stats.StatsPort),
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{
			{
				Filters: []*listener.Filter{
					{
						Name: wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{
							util.ToAny(recv.log, &hcm.HttpConnectionManager{
								StatPrefix: "stats",
								RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
									RouteConfig: &route.RouteConfiguration{
										VirtualHosts: []*route.VirtualHost{
											{
												Name:    "stats",
												Domains: []string{"*"},
												Routes: []*route.Route{
													{
														Match: &route.RouteMatch{
															PathSpecifier: &route.RouteMatch_Prefix{
																Prefix: "/stats",
															},
														},
														Action: &route.Route_Route{
															Route: &route.RouteAction{
																ClusterSpecifier: &route.RouteAction_Cluster{
																	Cluster: constants.StatsCluster,
																},
																Timeout: timeout,
															},
														},
													},
												},
											},
										},
									},
								},
								HttpFilters: []*hcm.HttpFilter{
									{
										Name: wellknown.Router,
										ConfigType: &hcm.HttpFilter_TypedConfig{
											TypedConfig: util.ToAny(recv.log, &router.Router{}),
										},
									},
								},
							}),
						},
					},
				},
			},
		},
	})
}

func LoadListenerConfig(log log15.Logger, lc *ListenerConfig) (success bool) {
	if config.ListenersConfigPath() == "" {
		log.Crit("missing LISTENERS_CONFIG_PATH")
		return
	}

	f, err := os.Open(config.ListenersConfigPath())
	if err != nil {
		log.Crit("os.Open", "Error", err)
		return
	}
	defer f.Close()

	err = json.NewDecoder(f).Decode(lc)
	if err != nil {
		log.Crit("json.Decode", "Error", err)
		return
	}

	if len(lc.IngressClasses) == 0 {
		log.Crit("no traffic classes defined in listener config")
		// could be nil. don't panic elsewhere
		lc.IngressClasses = make(map[string]IngressClass)
		return
	}

	if lc.Stats.StatsPort != 0 && lc.Stats.AdminPort == 0 {
		log.Crit("stats_port present but admin_port missing")
		return
	}

	if config.Testing() {
		if _, exists := lc.IngressClasses[constants.TestIngressClass]; !exists {
			log.Crit("missing ingress class in listener config")
			return
		}
	}
	if _, ok := lc.IngressClasses[constants.AuthzClass]; !ok {
		lc.IngressClasses[constants.AuthzClass] = IngressClass{
			Ports: map[string]PortInfo{},
		}
	}
	if _, ok := lc.IngressClasses[constants.RatelimitClass]; !ok {
		lc.IngressClasses[constants.RatelimitClass] = IngressClass{
			Ports: map[string]PortInfo{},
		}
	}
	for _, ic := range lc.IngressClasses {
		if ic.Tracing != nil {
			if ic.Tracing.TargetUri == "" {
				ic.Tracing.TargetUri = "127.0.0.1:4317"
			}
			if ic.Tracing.ServiceName == "" {
				ic.Tracing.ServiceName = "cluster-gateway"
			}
		}
	}

	success = true
	return
}
