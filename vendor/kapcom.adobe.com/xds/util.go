package xds

import (
	"kapcom.adobe.com/util"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"gopkg.in/inconshreveable/log15.v2"
)

func MapVHosts(rc *route.RouteConfiguration, cb func(*route.VirtualHost)) {
	if rc == nil || cb == nil {
		return
	}

	for _, vh := range rc.VirtualHosts {
		cb(vh)
	}
}

func MapClusterNames(vh *route.VirtualHost, cb func(string)) {
	if vh == nil || cb == nil {
		return
	}

	for _, vhRoute := range vh.Routes {
		if vhRoute.Action == nil {
			continue
		}

		rr, ok := vhRoute.Action.(*route.Route_Route)
		if !ok || rr.Route == nil {
			continue
		}

		switch cs := rr.Route.ClusterSpecifier.(type) {
		case *route.RouteAction_WeightedClusters:
			if cs.WeightedClusters == nil {
				continue
			}

			for _, cluster := range cs.WeightedClusters.Clusters {
				cb(cluster.Name)
			}

		case *route.RouteAction_Cluster:
			cb(cs.Cluster)
		}
	}
}

func MapTCPProxyClusters(log log15.Logger, lr *listener.Listener, cb func(string)) {
	if lr == nil || cb == nil {
		return
	}

	for _, fc := range lr.FilterChains {
		for _, filter := range fc.Filters {
			if filter.Name != wellknown.TCPProxy || filter.ConfigType == nil {
				continue
			}

			ftc, ok := filter.ConfigType.(*listener.Filter_TypedConfig)
			if !ok {
				continue
			}

			msg := util.FromAny(log, ftc.TypedConfig)
			if msg == nil {
				continue
			}

			tcpProxy, ok := msg.(*tcp_proxy.TcpProxy)
			if !ok {
				continue
			}

			switch cs := tcpProxy.ClusterSpecifier.(type) {
			case *tcp_proxy.TcpProxy_WeightedClusters:
				if cs.WeightedClusters == nil {
					continue
				}

				for _, cluster := range cs.WeightedClusters.Clusters {
					cb(cluster.Name)
				}

			case *tcp_proxy.TcpProxy_Cluster:
				cb(cs.Cluster)
			}
		}
	}
}
