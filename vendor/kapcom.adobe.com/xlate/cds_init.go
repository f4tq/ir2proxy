package xlate

import (
	"time"

	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/xds"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/golang/protobuf/ptypes"
)

func (recv *CRDHandler) initStatsCluster() {
	recv.statsCluster = xds.NewWrapper(&cluster.Cluster{
		Name:           constants.StatsCluster,
		ConnectTimeout: ptypes.DurationProto(10 * time.Millisecond),
		ClusterDiscoveryType: &cluster.Cluster_Type{
			Type: cluster.Cluster_STATIC,
		},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: constants.StatsCluster,
			Endpoints:   llbEndpoints("127.0.0.1", uint32(recv.lc.Stats.AdminPort)),
		},
	})
}
