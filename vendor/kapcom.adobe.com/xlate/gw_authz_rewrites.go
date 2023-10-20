package xlate

import (
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/util"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	dynfwd_cluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dynfwd_common "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dynfwd_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	lua_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
	"gopkg.in/inconshreveable/log15.v2"
)

const (
	// DefaultAuthRewriteClustersLen is the default number of clusters added
	DefaultAuthRewriteClustersLen = 2
)

// GetAuthzRewriteClusters gets the clusters necessary for
// rewritting requests after the authz filter.
func GetAuthzRewriteClusters(log log15.Logger) (clusters []*cluster.Cluster) {
	if !config.ExtAuthzRewrites() {
		return
	}

	commonTlsContext := &tls.CommonTlsContext{
		ValidationContextType: &tls.CommonTlsContext_ValidationContext{
			ValidationContext: &tls.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_Filename{
						Filename: config.UpstreamTrustedCertsPath(),
					},
				},
			},
		},
	}

	clusters = []*cluster.Cluster{
		{
			Name:           constants.DynForwardProxyClusterName,
			ConnectTimeout: &duration.Duration{Seconds: 5},
			LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
			UpstreamConnectionOptions: &cluster.UpstreamConnectionOptions{
				TcpKeepalive: &core.TcpKeepalive{
					KeepaliveProbes: &wrappers.UInt32Value{
						Value: uint32(3),
					},
					KeepaliveTime: &wrappers.UInt32Value{
						Value: uint32(30),
					},
					KeepaliveInterval: &wrappers.UInt32Value{
						Value: uint32(10),
					},
				},
			},
			ClusterDiscoveryType: &cluster.Cluster_ClusterType{
				ClusterType: &cluster.Cluster_CustomClusterType{
					Name: constants.DynForwardProxyCluster,
					TypedConfig: util.ToAny(log, &dynfwd_cluster.ClusterConfig{
						DnsCacheConfig: &dynfwd_common.DnsCacheConfig{
							Name: constants.DynForwardProxyClusterName,
							// Envoy has a DNS resolution preference for IPv6 and to fall back to IPv4.
							// However, this can lead to some connectivity issues when the DNS server
							// returns an IPv6 address that is not reachable. Force IPv4 resolutions.
							DnsLookupFamily: cluster.Cluster_V4_ONLY,
						},
					}),
				},
			},
		},
		{
			Name:           constants.DynForwardProxyClusterTLSName,
			ConnectTimeout: &duration.Duration{Seconds: 5},
			LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
			UpstreamConnectionOptions: &cluster.UpstreamConnectionOptions{
				TcpKeepalive: &core.TcpKeepalive{
					KeepaliveProbes: &wrappers.UInt32Value{
						Value: uint32(3),
					},
					KeepaliveTime: &wrappers.UInt32Value{
						Value: uint32(30),
					},
					KeepaliveInterval: &wrappers.UInt32Value{
						Value: uint32(10),
					},
				},
			},
			ClusterDiscoveryType: &cluster.Cluster_ClusterType{
				ClusterType: &cluster.Cluster_CustomClusterType{
					Name: constants.DynForwardProxyCluster,
					TypedConfig: util.ToAny(log, &dynfwd_cluster.ClusterConfig{
						DnsCacheConfig: &dynfwd_common.DnsCacheConfig{
							Name:            constants.DynForwardProxyClusterName,
							DnsLookupFamily: cluster.Cluster_V4_ONLY, // see previous comment
						},
					}),
				},
			},
			TransportSocket: &core.TransportSocket{
				Name: wellknown.TransportSocketTLS,
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: util.ToAny(log, &tls.UpstreamTlsContext{
						CommonTlsContext: commonTlsContext,
					}),
				},
			},
		},
	}
	return
}

// GetAuthzRewriteHTTPFilters returns the HTTP filters
// necessary for processing rewrites.
func GetAuthzRewriteHTTPFilters(log log15.Logger) (filters []*hcm.HttpFilter) {
	if !config.ExtAuthzRewrites() {
		return
	}

	filters = []*hcm.HttpFilter{
		{
			Name: wellknown.Lua,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: util.ToAny(log, &lua_http.Lua{
					SourceCodes: map[string]*core.DataSource{
						constants.LuaRewritePathScript: {
							Specifier: &core.DataSource_InlineString{
								InlineString: constants.LuaRewritePathScriptContents,
							},
						},
					},
				}),
			},
		},
		{
			Name: constants.DynFwdProxyFilter,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: util.ToAny(log, &dynfwd_http.FilterConfig{
					DnsCacheConfig: &dynfwd_common.DnsCacheConfig{
						Name:            constants.DynForwardProxyClusterName,
						DnsLookupFamily: cluster.Cluster_V4_ONLY, // see previous comment
					},
				}),
			},
		},
	}
	return
}

// GetAuthzRewriteRoutes gets the routes necessary for
// matching the rewrites after the authz filter.
func GetAuthzRewriteRoutes(log log15.Logger) (routes []*route.Route) {
	if !config.ExtAuthzRewrites() {
		return
	}

	// prepend a route for the dynamic forward proxy rewrite of the host header
	// and the dynamic forward proxy filter
	routes = []*route.Route{
		{
			Match: &route.RouteMatch{
				// this matches all the redirections that should go to a TLS upstream
				// (specified with the )
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
				Headers: []*route.HeaderMatcher{
					{
						Name:                 constants.HostPortRewriteHeader,
						HeaderMatchSpecifier: &route.HeaderMatcher_PresentMatch{PresentMatch: true},
					},
					{
						Name: constants.ProtocolRewriteHeader,
						HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
							StringMatch: &matcher.StringMatcher{
								MatchPattern: &matcher.StringMatcher_Exact{
									Exact: "tls",
								},
							},
						},
					},
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: constants.DynForwardProxyClusterTLSName,
					},
				},
			},
			TypedPerFilterConfig: map[string]*any.Any{
				wellknown.Lua: util.ToAny(log,
					&lua_http.LuaPerRoute{
						Override: &lua_http.LuaPerRoute_Name{
							Name: constants.LuaRewritePathScript,
						},
					}),
				constants.DynFwdProxyFilter: util.ToAny(log,
					&dynfwd_http.PerRouteConfig{
						HostRewriteSpecifier: &dynfwd_http.PerRouteConfig_HostRewriteHeader{
							HostRewriteHeader: constants.HostPortRewriteHeader,
						},
					}),
			},
			ResponseHeadersToRemove: []string{
				constants.HostPortRewriteHeader,
				constants.ProtocolRewriteHeader,
				constants.PathRewriteHeader,
			},
		},
		{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
				// match the header, x-rewrite-host-port, that the dynamic forward proxy filter uses
				// to rewrite the host header
				Headers: []*route.HeaderMatcher{
					{
						Name:                 constants.HostPortRewriteHeader,
						HeaderMatchSpecifier: &route.HeaderMatcher_PresentMatch{PresentMatch: true},
					},
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: constants.DynForwardProxyClusterName,
					},
				},
			},
			TypedPerFilterConfig: map[string]*any.Any{
				wellknown.Lua: util.ToAny(log,
					&lua_http.LuaPerRoute{
						Override: &lua_http.LuaPerRoute_Name{
							Name: constants.LuaRewritePathScript,
						},
					}),
				constants.DynFwdProxyFilter: util.ToAny(log,
					&dynfwd_http.PerRouteConfig{
						HostRewriteSpecifier: &dynfwd_http.PerRouteConfig_HostRewriteHeader{
							HostRewriteHeader: constants.HostPortRewriteHeader,
						},
					}),
			},
			ResponseHeadersToRemove: []string{
				constants.HostPortRewriteHeader,
				constants.ProtocolRewriteHeader,
				constants.PathRewriteHeader,
			},
		},
	}
	return
}

// GetRoutesDisabledLua processes the routes and explicitly disables the Lua filter
// if no Lua filter configuration is present.
func GetRoutesDisabledLua(log log15.Logger, routes []*route.Route) []*route.Route {
	res := []*route.Route{}
	for _, route := range routes {
		if route.TypedPerFilterConfig == nil {
			route.TypedPerFilterConfig = make(map[string]*any.Any)
		}

		if _, ok := route.TypedPerFilterConfig[wellknown.Lua]; !ok {
			route.TypedPerFilterConfig[wellknown.Lua] = util.ToAny(log, &lua_http.LuaPerRoute{
				Override: &lua_http.LuaPerRoute_Disabled{Disabled: true},
			})
		}

		res = append(res, route)
	}
	return res
}

// FilterOutAuthzRewriteClusters is an utility function that filters out the clusters
// used for rewrites.
func FilterOutAuthzRewriteClusters(clusters []*cluster.Cluster) []*cluster.Cluster {
	var filtered []*cluster.Cluster
	for _, c := range clusters {
		if c.Name == constants.DynForwardProxyClusterName || c.Name == constants.DynForwardProxyClusterTLSName {
			continue
		}
		filtered = append(filtered, c)
	}
	return filtered
}
