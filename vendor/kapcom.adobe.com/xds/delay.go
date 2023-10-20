package xds

import (
	"kapcom.adobe.com/set"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/golang/protobuf/proto"
)

func (recv *envoyConnection) delayXDS(typeUrl TypeURL, added, removed set.Set) {
	// special case for CDS warming to remove RDS entries if needed
	recv.delayRDS(typeUrl, added)

	// special case to delay removal of stale CDS (and corresponding EDS)
	recv.delayCDS(typeUrl, removed)
}

func (recv *envoyConnection) checkDelayedXDS(typeUrl TypeURL, acks set.Set) {
	// special case for RDS to send previously delayed RDS
	recv.checkCDSWarmed(typeUrl, acks)

	// also for previously delayed CDS/EDS
	recv.checkRDSAcked(typeUrl)
}

// for new clusters we must wait to send RDS until they've been warmed
func (recv *envoyConnection) delayRDS(typeUrl TypeURL, resources set.Set) {
	if typeUrl != RouteType {
		return
	}

	clustersInFlight := make(map[string]interface{})
	for _, nonceResources := range recv.cds.envoyAddNonces {
		for clusterName := range nonceResources {
			clustersInFlight[clusterName] = nil
		}
	}

	if len(clustersInFlight) == 0 {
		return
	}

	// updates will be in ACK tracking. new clusters won't
	clustersWarming := set.Difference(clustersInFlight, recv.cds.envoyACKed)

	if len(clustersWarming) == 0 {
		return
	}

	resourcesToDelay := set.New()

	for name, iface := range resources {
		iface.(Wrapper).Write(func(msg proto.Message, meta *interface{}) (protoChanged bool) {
			rc := msg.(*route.RouteConfiguration)
			rcMeta := (*meta).(*RouteConfigurationMeta)
			rcMeta.ClustersWarming = set.New()

			MapVHosts(rc, func(vh *route.VirtualHost) {
				MapClusterNames(vh, func(clusterName string) {
					if _, exists := clustersWarming[clusterName]; exists {
						rcMeta.ClustersWarming[clusterName] = nil
						resourcesToDelay[name] = nil
					}
				})
			})

			return
		})
	}

	for name := range resourcesToDelay {
		recv.log.Info("delaying RDS", "name", name)
		delete(resources, name)
	}
}

func (recv *envoyConnection) checkCDSWarmed(typeUrl TypeURL, acks set.Set) {
	if typeUrl != ClusterType {
		return
	}

	anyWarmed := false

	for _, iface := range *recv.rds.sotw.Load() {
		iface.(Wrapper).Read(func(msg proto.Message, meta interface{}) {
			rcMeta := (meta).(*RouteConfigurationMeta)

			if set.Intersects(rcMeta.ClustersWarming, acks) {
				anyWarmed = true
			}
		})

		if anyWarmed {
			break
		}
	}

	if anyWarmed {
		recv.thisChan <- internalDDRMsg{RouteType}
	}
}

// if we have stale CDS, delay CDS/EDS removal until all RDS is ack-ed
func (recv *envoyConnection) delayCDS(typeUrl TypeURL, resources set.Set) {
	if typeUrl != ClusterType && typeUrl != EndpointType {
		return
	}

	if recv.staleCDS {
		resourcesToDelay := make([]string, 0, len(resources))
		for name := range resources {
			resourcesToDelay = append(resourcesToDelay, name)
		}

		for _, name := range resourcesToDelay {
			recv.log.Info("delaying CDS/EDS", "name", name, "typeUrl", typeUrl)
			delete(resources, name)
		}
	}
}

func (recv *envoyConnection) checkRDSAcked(typeUrl TypeURL) {
	if typeUrl != RouteType {
		return
	}

	if recv.staleCDS && len(recv.rds.envoyACKed) >= len(*recv.rds.sotw.Load()) {
		recv.staleCDS = false
		recv.thisChan <- internalDDRMsg{ClusterType}
		recv.thisChan <- internalDDRMsg{EndpointType}
	}
}
