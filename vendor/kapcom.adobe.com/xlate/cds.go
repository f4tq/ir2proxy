package xlate

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/constants/annotations"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xds"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
	"gopkg.in/inconshreveable/log15.v2"
	k8s "k8s.io/api/core/v1"
)

type mutateClusterInput struct {
	role         EnvoyRole
	clusterName  string
	altStatName  string
	externalName string
	h2           bool
	tls          bool
	xCluster     Cluster
	c            *cluster.Cluster
	kServicePort *k8s.ServicePort
	endpointsLen uint32
	mtls         *mTLS
	mtlsH2       bool
}

func defaultDuration(default_, val time.Duration) *duration.Duration {
	if val != 0 {
		return ptypes.DurationProto(val)
	}
	return ptypes.DurationProto(default_)
}

func defaultCount(default_, val uint32) *wrappers.UInt32Value {
	if val != 0 {
		return &wrappers.UInt32Value{Value: val}
	}
	return &wrappers.UInt32Value{Value: default_}
}

func llbEndpoints(address string, port uint32) []*endpoint.LocalityLbEndpoints {
	return []*endpoint.LocalityLbEndpoints{
		{
			LbEndpoints: []*endpoint.LbEndpoint{
				{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Address: address,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: port,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (recv *CRDHandler) mutateTransportSocket(cl *cluster.Cluster) {
	if !config.MTLS() {
		return
	}
	if cl.Http2ProtocolOptions == nil {
		// cluster services are grpc which requires h2
		// make sure it's on but accepting what's provided otherwise
		cl.Http2ProtocolOptions = &core.Http2ProtocolOptions{}
	}
	utc := &tls.UpstreamTlsContext{
		CommonTlsContext: &tls.CommonTlsContext{
			TlsParams: constants.MTLSParams,
			// mTLS does not use SDS because eventual consistency isn't
			// fast enough and because it simplified the implementation
			// by not having to maintain SDS
			TlsCertificates:       []*tls.TlsCertificate{secretToTlsCert(recv.mtls.clientSecret)},
			AlpnProtocols:         []string{"h2"},
			ValidationContextType: recv.mtls.caCerts,
		},
	}
	cl.TransportSocket = &core.TransportSocket{
		Name: wellknown.TransportSocketTls,
		ConfigType: &core.TransportSocket_TypedConfig{
			util.ToAny(recv.log, utc),
		},
	}
}

func mutateClusterByRole(log log15.Logger, mci mutateClusterInput) {

	role := mci.role
	clusterName := mci.clusterName
	externalName := mci.externalName
	h2 := mci.h2
	xCluster := mci.xCluster
	c := mci.c
	kServicePort := mci.kServicePort

	switch role {
	case GatewayRole:

		if externalName == "" {
			c.ClusterDiscoveryType = &cluster.Cluster_Type{
				Type: cluster.Cluster_EDS,
			}

			c.EdsClusterConfig = &cluster.Cluster_EdsClusterConfig{
				EdsConfig: xds.ConfigSource(),
			}
		} else {
			c.ClusterDiscoveryType = &cluster.Cluster_Type{
				Type: cluster.Cluster_STRICT_DNS,
			}

			c.LoadAssignment = &endpoint.ClusterLoadAssignment{
				ClusterName: clusterName,
				Endpoints:   llbEndpoints(externalName, uint32(xCluster.Port)),
			}
		}

		c.UpstreamConnectionOptions = &cluster.UpstreamConnectionOptions{
			TcpKeepalive: &core.TcpKeepalive{
				KeepaliveProbes:   &wrappers.UInt32Value{Value: 3},
				KeepaliveTime:     &wrappers.UInt32Value{Value: 90},
				KeepaliveInterval: &wrappers.UInt32Value{Value: 90},
			},
		}

		if xCluster.ConnectTimeout == 0 {
			// this value needs to support externalName (egressing the cluster)
			// as well as mTLS where the handshake is included in this duration
			c.ConnectTimeout = ptypes.DurationProto(250 * time.Millisecond)
		} else {
			c.ConnectTimeout = ptypes.DurationProto(xCluster.ConnectTimeout)
		}

		// https://github.com/envoyproxy/envoy/issues/8056
		// https://github.com/envoyproxy/envoy/issues/11027
		c.IgnoreHealthOnHostRemoval = true

		c.CircuitBreakers = &cluster.CircuitBreakers{
			Thresholds: []*cluster.CircuitBreakers_Thresholds{
				{
					MaxConnections:     xCluster.EndpointCircuitBreaker.maxConnections(mci.endpointsLen),
					MaxPendingRequests: xCluster.EndpointCircuitBreaker.maxPendingRequests(mci.endpointsLen),
					MaxRequests:        xCluster.EndpointCircuitBreaker.maxRequests(mci.endpointsLen),
					// MaxRetries: Envoy default
				},
			},
		}

		c.CommonLbConfig = &cluster.Cluster_CommonLbConfig{
			HealthyPanicThreshold: &envoy_type.Percent{Value: 10},
			// TODO(bcook) revisit this
			// IgnoreNewHostsUntilFirstHc: true,
		}

		var utc *tls.UpstreamTlsContext
		if mci.tls {
			utc = &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{},
				// TODO(lrouquet): upstream secret validation
			}
			if h2 {
				utc.CommonTlsContext.AlpnProtocols = []string{"h2"}
			}
		} else if mtls := mci.mtls; mtls != nil {
			// because envoy doesn't support multi certs on the upstream or downstream certs, use the oldest client cert
			// otherwise, face possible timing issue with the sidecar not yet having the cert in place
			utc = &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: constants.MTLSParams,
					// mTLS does not use SDS because eventual consistency isn't
					// fast enough and because it simplified the implementation
					// by not having to maintain SDS
					TlsCertificates:       []*tls.TlsCertificate{secretToTlsCert(mtls.clientSecret)},
					ValidationContextType: mtls.caCerts,
				},
			}

			// TODO(bcook) figure out why this is causing 503s and consider removing
			// if mci.mtlsH2 {
			// 	utc.CommonTlsContext.AlpnProtocols = []string{"h2"}
			// 	c.Http2ProtocolOptions = &core.Http2ProtocolOptions{}
			// }
		}

		if utc != nil {
			c.TransportSocket = &core.TransportSocket{
				Name: wellknown.TransportSocketTls,
				ConfigType: &core.TransportSocket_TypedConfig{
					util.ToAny(log, utc),
				},
			}
		}

		c.LbPolicy = xCluster.LbPolicy
		if xCluster.LeastRequestLbConfig != nil {
			c.LbConfig = &cluster.Cluster_LeastRequestLbConfig_{
				LeastRequestLbConfig: &cluster.Cluster_LeastRequestLbConfig{
					ChoiceCount: &wrappers.UInt32Value{Value: xCluster.LeastRequestLbConfig.ChoiceCount},
				},
			}
		}

		// TODO(bcook) for mTLS this needs to be dynamic and less than the
		// Sidecar's --drain-time-s to avoid the issue described in
		// https://medium.com/@phylake/why-idle-timeouts-matter-1b3f7d4469fe?sk=9915bbe0200185e6929e942f289abf08
		if xCluster.IdleTimeout == 0 {
			c.CommonHttpProtocolOptions = &core.HttpProtocolOptions{
				IdleTimeout: ptypes.DurationProto(58 * time.Second),
			}
		} else {
			c.CommonHttpProtocolOptions = &core.HttpProtocolOptions{
				IdleTimeout: ptypes.DurationProto(xCluster.IdleTimeout),
			}
		}

		if hc := xCluster.HealthCheck; hc != nil {

			var hostHeader string
			if hc.Host == "" {
				hostHeader = constants.ProgramNameLower + "-envoy-healthcheck"
			} else {
				hostHeader = hc.Host
			}

			c.HealthChecks = []*core.HealthCheck{
				{
					Timeout:               defaultDuration(2*time.Second, hc.Timeout),
					Interval:              defaultDuration(10*time.Second, hc.Interval),
					InitialJitter:         defaultDuration(time.Second, time.Second),
					IntervalJitterPercent: 100,
					UnhealthyThreshold:    defaultCount(3, hc.UnhealthyThreshold),
					HealthyThreshold:      defaultCount(2, hc.HealthyThreshold),
					// default is true but being explicit protects us during
					// protobuf major version upgrades
					ReuseConnection: &wrappers.BoolValue{Value: true},
					HealthChecker: &core.HealthCheck_HttpHealthCheck_{
						HttpHealthCheck: &core.HealthCheck_HttpHealthCheck{
							Host: hostHeader,
							Path: hc.Path,
							// [200, 400) so 200-399 to match K8s probes
							ExpectedStatuses: []*envoy_type.Int64Range{
								{
									Start: 200,
									End:   400,
								},
							},
						},
					},
				},
			}

			if config.LogHealthCheckFailures() {
				c.HealthChecks[0].EventLogPath = "/dev/stderr"
				c.HealthChecks[0].AlwaysLogHealthCheckFailures = true
			}
		}

	case SidecarRole:

		c.ConnectTimeout = ptypes.DurationProto(100 * time.Millisecond)

		c.ClusterDiscoveryType = &cluster.Cluster_Type{
			Type: cluster.Cluster_STATIC,
		}

		c.LoadAssignment = &endpoint.ClusterLoadAssignment{
			ClusterName: clusterName,
			Endpoints:   llbEndpoints("127.0.0.1", uint32(kServicePort.TargetPort.IntValue())),
		}

	} // switch
}

func mutateCluster(log log15.Logger, mci mutateClusterInput) {

	c := mci.c
	h2 := mci.h2

	c.Name = mci.clusterName
	c.AltStatName = mci.altStatName

	if h2 {
		c.Http2ProtocolOptions = &core.Http2ProtocolOptions{}
	}

	mutateClusterByRole(log, mci)
}

func (recv *CRDHandler) createClusters(sotw SotW, ingress *Ingress,
	clusters []Cluster, mtlsH2 bool) (shouldUpdateCDS bool) {

	nsCRDs := recv.getNS(ingress.Namespace)

	for _, xCluster := range clusters {
		var kService *k8s.Service
		var exists bool
		if kService, exists = nsCRDs.services[xCluster.Name]; !exists {
			continue
		}

		// list of port names/numbers that should use HTTP/2
		var h2PortsArr []string
		h2PortsArr = append(h2PortsArr, strings.Split(kService.Annotations[annotations.H2], ",")...)
		h2PortsArr = append(h2PortsArr, strings.Split(kService.Annotations[annotations.H2C], ",")...)
		h2Ports := arr2map(h2PortsArr)

		// list of port names/numbers that should use TLS
		var tlsPortsArr []string
		tlsPortsArr = append(tlsPortsArr, strings.Split(kService.Annotations[annotations.H2], ",")...)
		tlsPortsArr = append(tlsPortsArr, strings.Split(kService.Annotations[annotations.TLS], ",")...)
		tlsPorts := arr2map(tlsPortsArr)

		for _, kServicePort := range kService.Spec.Ports {
			// match only the port declared by the Ingress's Cluster
			// the K8s Service could expose more ports
			if !xCluster.MatchServicePort(kServicePort, k8s.ProtocolTCP) {
				continue
			}

			_, h2Port := h2Ports[strconv.FormatInt(int64(kServicePort.Port), 10)]
			_, h2Name := h2Ports[kServicePort.Name]
			h2 := h2Port || h2Name
			if ingress.IsClusterService() {
				h2 = true
			}

			_, tlsPort := tlsPorts[strconv.FormatInt(int64(kServicePort.Port), 10)]
			_, tlsName := tlsPorts[kServicePort.Name]
			tls := tlsPort || tlsName

			clusterName := ClusterName(&xCluster, kService, &kServicePort)
			altStatName := AltStatName(kService, &kServicePort)

			var wrapper xds.Wrapper
			if iface, exists := sotw.cds[clusterName]; exists {
				wrapper = iface.(xds.Wrapper)
			} else {
				wrapper = xds.NewWrapper(&cluster.Cluster{})
				sotw.cds[clusterName] = wrapper
			}

			endpointsLen := uint32(len(endpointsIPs(nsCRDs.endpoints[xCluster.Name])))

			mtls := recv.mTLSForIngress(ingress)

			newCluster := &cluster.Cluster{}
			mutateCluster(recv.log,
				mutateClusterInput{
					role:         sotw.role,
					clusterName:  clusterName,
					altStatName:  altStatName,
					externalName: kService.Spec.ExternalName,
					h2:           h2,
					tls:          tls,
					xCluster:     xCluster,
					c:            newCluster,
					kServicePort: &kServicePort,
					endpointsLen: endpointsLen,
					mtls:         mtls,
					mtlsH2:       mtlsH2,
				},
			)

			if wrapper.CompareAndReplace(recv.log, newCluster) {
				shouldUpdateCDS = true
			}
		}
	}
	return
}

func (recv *CRDHandler) handleMiscClusters(ingress *Ingress, sotw SotW, shouldUpdateCDS *bool) {
	if recv.statsCluster != nil {
		if _, exists := sotw.cds[constants.StatsCluster]; !exists {
			sotw.cds[constants.StatsCluster] = recv.statsCluster
			*shouldUpdateCDS = true
		}
	}

	if recv.rateLimitCluster != nil {
		if sotw.sidecar == nil {
			// gw side ratelimit cluster
			if _, exists := sotw.cds[RatelimitClusterName()]; !exists {

				// TODO(fortesque) reenable
				// if recv.canMTLS() && RateLimitInternalMTLS() {
				// 	rlCluster := RateLimitCluster()
				// 	recv.mutateTransportSocket(rlCluster)
				// }
				sotw.cds[RatelimitClusterName()] = recv.rateLimitCluster
				*shouldUpdateCDS = true
			}
		}
	}

	if recv.authzCluster != nil {
		if sotw.sidecar == nil {
			// gw side authz cluster
			if _, exists := sotw.cds[AuthzClusterName()]; !exists {
				// TODO(fortesque) reenable
				// if recv.canMTLS() && AuthzInternalMTLS() {
				// 	authzCluster := AuthzCluster()
				// 	recv.mutateTransportSocket(authzCluster)
				// }
				sotw.cds[AuthzClusterName()] = recv.authzCluster
				*shouldUpdateCDS = true
			}
		}
	}

	if sotw.sidecar != nil && sotw.sidecar.Spec.Filters.ExtAuthz != nil {
		// TODO: @bcook: do we still have a need for sidecar defined authz?
		//    it would be recursive if gw authz were on too
		if _, exists := sotw.cds[constants.ExtAuthzCluster]; !exists {
			cr := &cluster.Cluster{
				Name:                 constants.ExtAuthzCluster,
				ConnectTimeout:       ptypes.DurationProto(10 * time.Millisecond),
				Http2ProtocolOptions: &core.Http2ProtocolOptions{},
				ClusterDiscoveryType: &cluster.Cluster_Type{
					Type: cluster.Cluster_STRICT_DNS,
				},
				LbPolicy: cluster.Cluster_RANDOM,
				LoadAssignment: &endpoint.ClusterLoadAssignment{
					ClusterName: constants.ExtAuthzCluster,
					Endpoints: llbEndpoints(
						sotw.sidecar.Spec.Filters.ExtAuthz.GrpcService.SocketAddress.Address,
						uint32(sotw.sidecar.Spec.Filters.ExtAuthz.GrpcService.SocketAddress.PortValue),
					),
				},
			}
			// TODO(fortesque) reenable
			// recv.mutateTransportSocket(cluster)
			sotw.cds[constants.ExtAuthzCluster] = xds.NewWrapper(cr)
			*shouldUpdateCDS = true
		}
	}

	if len(ingress.VirtualHost.Logging.Loggers) > 0 && config.GrpcAlsEnabled() {
		if grpcLogger := ingress.VirtualHost.Logging.Loggers[0].GRPC; grpcLogger != nil {

			clusterName := GRPCClusterName(grpcLogger)

			if _, exists := sotw.cds[clusterName]; !exists {

				cr := &cluster.Cluster{
					Name:                 clusterName,
					ConnectTimeout:       ptypes.DurationProto(10 * time.Millisecond),
					Http2ProtocolOptions: &core.Http2ProtocolOptions{},
					ClusterDiscoveryType: &cluster.Cluster_Type{
						// ensure traffic is evenly distributed to gRPC ALSes
						Type: cluster.Cluster_STRICT_DNS,
					},
					LoadAssignment: &endpoint.ClusterLoadAssignment{
						ClusterName: clusterName,
						Endpoints:   llbEndpoints(grpcLogger.Host, uint32(grpcLogger.Port)),
					},
				}

				sotw.cds[clusterName] = xds.NewWrapper(cr)
				*shouldUpdateCDS = true
			}
		}
	}
}

func (recv *CRDHandler) updateCDS(ns, name string) {

	for _, ingress := range recv.getIngressList(ns, name) {

		// if an Ingress was previously valid we leave the CDS entries intact since
		// other Ingresses could still reference them
		if !ingress.Valid() {
			continue
		}

		for _, sotw := range recv.getSotWs(ingress) {
			shouldUpdateCDS := false

			recv.handleMiscClusters(ingress, sotw, &shouldUpdateCDS)

			if ingress.IsClusterService() && sotw.sidecar == nil {
				config.Log.Debug("updateCDS", "cluster_service", fmt.Sprintf("Skipping cluster_service ingress %s", ingress.Name))
			} else {
				if ingress.Listener.TCPProxy == nil {
					for _, route := range ingress.VirtualHost.ResolvedRoutes() {
						mtlsH2 := !route.WebsocketUpgrade && !route.SPDYUpgrade
						if recv.createClusters(sotw, ingress, route.Clusters, mtlsH2) {
							shouldUpdateCDS = true
						}
					}
				} else {
					if recv.createClusters(sotw, ingress, ingress.Listener.TCPProxy.Clusters, false) {
						shouldUpdateCDS = true
					}
				}
			}
			if shouldUpdateCDS {
				recv.updateSotW(sotw.subset, xds.ClusterType, sotw.cds)
			}
		}
	}
}
