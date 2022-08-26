package xlate

import (
	"net"
	"sort"

	"kapcom.adobe.com/xds"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	k8s "k8s.io/api/core/v1"
)

func endpointsToCLA(clusterName string, l4Addresses []l4Address,
	cla *endpoint.ClusterLoadAssignment) {

	sort.SliceStable(l4Addresses, func(a, b int) bool {
		aIP := net.ParseIP(l4Addresses[a].ip).To4()
		bIP := net.ParseIP(l4Addresses[b].ip).To4()
		if len(aIP) != 4 || len(bIP) != 4 {
			return false
		}

		// reverse the octets so IPs of the same subnet are not collocated
		//
		// this is important so host retries don't land on the same node when
		// lb_policy is ROUND_ROBIN
		aInt := uint32(aIP[0]) | uint32(aIP[1])<<8 | uint32(aIP[2])<<16 | uint32(aIP[3])<<24
		bInt := uint32(bIP[0]) | uint32(bIP[1])<<8 | uint32(bIP[2])<<16 | uint32(bIP[3])<<24

		return aInt < bInt
	})

	lbEndpoints := make([]*endpoint.LbEndpoint, len(l4Addresses))

	for i, l4Addr := range l4Addresses {
		lbEndpoints[i] = &endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Protocol: core.SocketAddress_TCP,
								Address:  l4Addr.ip,
								PortSpecifier: &core.SocketAddress_PortValue{
									PortValue: l4Addr.port,
								},
							},
						},
					},
				},
			},
		}
	}

	cla.ClusterName = clusterName
	cla.Endpoints = []*endpoint.LocalityLbEndpoints{
		{
			LbEndpoints: lbEndpoints,
		},
	}
}

func (recv *CRDHandler) updateEDS(ns, name string) {
	nsCRDs := recv.getNS(ns)

	shouldUpdateEDS := false

	sotw := recv.envoySubsets[xds.DefaultEnvoySubset]

	for _, ingress := range recv.getIngressList(ns, name) {

		// if an Ingress was previously valid we leave the EDS entries intact since
		// other Ingresses could still reference them
		if !ingress.Valid() {
			continue
		}

		handleCluster := func(cluster Cluster) {
			var (
				kService   *k8s.Service
				kEndpoints *k8s.Endpoints
				exists     bool
			)

			if kService, exists = nsCRDs.services[cluster.Name]; !exists {
				recv.log.Debug("updateEDS missing Service",
					"ns", ingress.Namespace, "name", cluster.Name)
				return
			}
			if kEndpoints, exists = nsCRDs.endpoints[cluster.Name]; !exists {
				recv.log.Debug("updateEDS missing Endpoints",
					"ns", ingress.Namespace, "name", cluster.Name)
				return
			}

			recv.log.Debug("updateEDS Service", "value", kService)
			recv.log.Debug("updateEDS Endpoints", "value", kEndpoints)

			for _, kServicePort := range kService.Spec.Ports {
				// match only the port declared by the Ingress's Cluster
				// the K8s Service could expose more ports
				if !cluster.MatchServicePort(kServicePort, k8s.ProtocolTCP) {
					continue
				}

				uniqueL4Addresses := make(map[l4Address]interface{})

				for _, subset := range kEndpoints.Subsets {

					for _, kEndpointPort := range subset.Ports {
						if kServicePort.Name != kEndpointPort.Name {
							continue
						}

						for _, address := range subset.Addresses {
							l4a := l4Address{
								ip:   address.IP,
								port: uint32(kEndpointPort.Port),
							}
							uniqueL4Addresses[l4a] = nil

							recv.log.Debug("updateEDS address",
								"ns", kEndpoints.Namespace, "name", kEndpoints.Name,
								"ip", l4a.ip, "port", l4a.port)
						}
					}
				}

				l4Addresses := make([]l4Address, 0, len(uniqueL4Addresses))
				for l4a := range uniqueL4Addresses {
					l4Addresses = append(l4Addresses, l4a)
				}

				clusterName := ClusterName(&cluster, kService, &kServicePort)

				var wrapper xds.Wrapper
				if iface, exists := sotw.eds[clusterName]; exists {
					wrapper = iface.(xds.Wrapper)
				} else {
					wrapper = xds.NewWrapper(&endpoint.ClusterLoadAssignment{})
					sotw.eds[clusterName] = wrapper
				}

				newCLA := &endpoint.ClusterLoadAssignment{}
				endpointsToCLA(clusterName, l4Addresses, newCLA)
				recv.log.Debug("endpointsToCLA", "newCLA", newCLA)

				if wrapper.CompareAndReplace(recv.log, newCLA) {
					shouldUpdateEDS = true
				}
			}
		}

		if ingress.Listener.TCPProxy == nil {
			for _, route := range ingress.VirtualHost.ResolvedRoutes() {
				for _, cluster := range route.Clusters {
					handleCluster(cluster)
				}
			}
		} else {
			for _, cluster := range ingress.Listener.TCPProxy.Clusters {
				handleCluster(cluster)
			}
		}
	}

	if shouldUpdateEDS {
		recv.updateSotW(xds.DefaultEnvoySubset, xds.EndpointType, sotw.eds)
	}
}
