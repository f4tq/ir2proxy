package xds

import (
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/util"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	grpc_log "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
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
			if filter.Name != wellknown.TCPProxy {
				continue
			}

			tcpProxy, ok := util.FromAny(log, filter.GetTypedConfig()).(*tcp_proxy.TcpProxy)
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

func MapGRPCALSClusters(log log15.Logger, lr *listener.Listener, cb func(string)) {
	if lr == nil || cb == nil {
		return
	}

	if config.DebugLogs() {
		log = log.New("f", "MapGRPCALSClusters")
	}

	for _, fc := range lr.FilterChains {
		for _, filter := range fc.Filters {
			if filter.Name != wellknown.HTTPConnectionManager {
				continue
			}

			hcmConfig, ok := util.FromAny(log, filter.GetTypedConfig()).(*hcm.HttpConnectionManager)
			if !ok {
				continue
			}

			for _, al := range hcmConfig.AccessLog {
				if al.Name != wellknown.HTTPGRPCAccessLog {
					continue
				}

				hgalc, ok := util.FromAny(log, al.GetTypedConfig()).(*grpc_log.HttpGrpcAccessLogConfig)
				if !ok {
					log.Debug("!msg.(*grpc_log.HttpGrpcAccessLogConfig)")
					continue
				}

				clusterName := hgalc.
					GetCommonConfig().
					GetGrpcService().
					GetEnvoyGrpc().
					GetClusterName()

				if clusterName != "" {
					cb(clusterName)
				}
			}
		}
	}
}
