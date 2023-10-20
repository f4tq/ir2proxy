package xds

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/metrics"
	"kapcom.adobe.com/set"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"gopkg.in/inconshreveable/log15.v2"
)

type TypeURL string

const (
	ClusterType  TypeURL = resource.ClusterType
	EndpointType TypeURL = resource.EndpointType
	ListenerType TypeURL = resource.ListenerType
	RouteType    TypeURL = resource.RouteType
	SecretType   TypeURL = resource.SecretType

	// envoy-cluster-gateway.yaml and what we set --service-cluster to in libsonnet
	DefaultEnvoySubset EnvoySubset = "cluster-gateway"

	xdsWarnThresholdPercent int = 90 // a %-age
)

type (
	EnvoySubset string

	uniqueStreams map[uint64]interface{}

	sotw struct {
		cds set.Set
		eds set.Set
		lds set.Set
		rds set.Set
		sds set.Set
	}

	adsServerImpl struct {
		log           log15.Logger
		streamCounter *uint64
		serverChan    chan interface{}

		// we don't organize this like xlate does because we don't know to which
		// subset an Envoy connection belongs until the first DiscoveryRequest
		nodeEnvoys    map[uint64]*envoyConnection
		subsetStreams map[EnvoySubset]uniqueStreams
		sotwSubsets   map[EnvoySubset]*sotw

		xdsWarnThreshold int
	}
)

var (
	adsServer *adsServerImpl

	xdsEnvoyConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: constants.ProgramNameLower,
		Subsystem: "xds",
		Name:      "envoy_connections",
		Help:      "Current number of Envoy connections.",
	})
	xdsServerchanBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: constants.ProgramNameLower,
		Subsystem: "xds",
		Name:      "serverchan_backlog",
		Help:      "Current serverchan backlog.",
	})
	xdsStateChanges = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: constants.ProgramNameLower,
		Subsystem: "xds",
		Name:      "state_changes",
		Help:      "Total number of xDS state changes.",
	})
	grpcMetrics = grpc_prometheus.NewServerMetrics(
		grpc_prometheus.CounterOption(func(o *prometheus.CounterOpts) {
			o.Namespace = constants.ProgramNameLower
			o.Subsystem = "xds"
		}),
	)
)

func init() {
	prometheus.MustRegister(xdsEnvoyConnections)
	prometheus.MustRegister(xdsServerchanBacklog)
	prometheus.MustRegister(xdsStateChanges)
	prometheus.MustRegister(grpcMetrics)
}

func (recv TypeURL) XDS() string {
	switch recv {
	case ClusterType:
		return "CDS"
	case EndpointType:
		return "EDS"
	case ListenerType:
		return "LDS"
	case RouteType:
		return "RDS"
	case SecretType:
		return "SDS"
	}
	return ""
}

func (recv *adsServerImpl) newEnvoyConnection() *envoyConnection {
	// assume concurrent calls to
	// type AggregatedDiscoveryServiceClient interface
	// functions
	streamId := atomic.AddUint64(recv.streamCounter, 1)

	return &envoyConnection{
		log:      recv.log.New("s", streamId),
		streamId: streamId,
		// nodeId not known until the first DiscoveryRequest
		// nodeCluster not known until the first DiscoveryRequest
		// detailedMetrics set elsewhere
		// delta set elsewhere
		// deltaChan set elsewhere
		serverChanSend: recv.serverChanSend,

		// buffered enough to avoid "channel full" logs in our largest clusters
		thisChan: make(chan interface{}, config.XDSBacklog()),

		cds: newXDSState(),
		eds: newXDSState(),
		lds: newXDSState(),
		rds: newXDSState(),
		sds: newXDSState(),
	}
}

func (recv *adsServerImpl) newDeltaEnvoyConnection(delta discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) *envoyConnection {
	envoyConn := recv.newEnvoyConnection()
	envoyConn.delta = delta
	envoyConn.deltaChan = make(chan *discovery.DeltaDiscoveryRequest, 1)
	return envoyConn
}

func (recv *adsServerImpl) StreamAggregatedResources(stream discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	return errors.New("StreamAggregatedResources not implemented")
}

func (recv *adsServerImpl) DeltaAggregatedResources(delta discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	envoyConn := recv.newDeltaEnvoyConnection(delta)
	recv.log.Info("envoy connect", "s", envoyConn.streamId)
	recv.serverChanSend(envoyConnCreatedMsg{envoyConn})

	envoyConn.run()

	recv.log.Info("envoy disconnect", "s", envoyConn.streamId, "ni", envoyConn.nodeId)
	recv.serverChanSend(envoyConnDestroyedMsg{envoyConn})
	return nil
}

func (recv *adsServerImpl) getSotWSubset(subset EnvoySubset) (s *sotw) {
	var exists bool
	if s, exists = recv.sotwSubsets[subset]; !exists {
		s = &sotw{
			cds: set.New(),
			eds: set.New(),
			lds: set.New(),
			rds: set.New(),
			sds: set.New(),
		}
		recv.sotwSubsets[subset] = s
	}
	return
}

func (recv *adsServerImpl) getSubsetStreams(subset EnvoySubset) (streams uniqueStreams) {
	var exists bool
	if streams, exists = recv.subsetStreams[subset]; !exists {
		streams = make(uniqueStreams)
		recv.subsetStreams[subset] = streams
	}
	return
}

func (recv *adsServerImpl) serverChanSend(iface interface{}) {
	xdsServerchanBacklog.Inc()
	recv.serverChan <- iface
}

func (recv *adsServerImpl) channelMonitor(ctx context.Context) {
	t := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			recv.log.Info("XDS channelMonitor stopping")
			return
		case <-t.C:
			t.Reset(10 * time.Second)

			backlog := len(recv.serverChan)
			if backlog > 0 {
				recv.log.Info("serverChan backlog", "len", backlog)
			}
		}
	}
}

func (recv *adsServerImpl) loop(ctx context.Context, resetChan <-chan struct{}) {
	t := time.NewTimer(0)

	for {
		select {
		case <-ctx.Done():
			recv.log.Info("XDS server stopping")
			for _, envoyConn := range recv.nodeEnvoys {
				envoyConn.thisChan <- shutdownMsg{normalExit}
			}
			recv.log.Info("XDS server stopped")
			return

		case <-resetChan:
			for _, envoyConn := range recv.nodeEnvoys {
				envoyConn.thisChan <- shutdownMsg{normalExit}
			}

		case <-t.C:
			t.Reset(1 * time.Minute)
			for subset, sotw := range recv.sotwSubsets {
				recv.log.Info("XDS info",
					"subset", subset,
					"envoy_connections", len(recv.subsetStreams[subset]),
					"clusters", len(sotw.cds),
					"endpoints", len(sotw.eds),
					"listeners", len(sotw.lds),
					"routes", len(sotw.rds),
					"secrets", len(sotw.sds),
				)
			}

		case iface := <-recv.serverChan:
			xdsServerchanBacklog.Dec()

			switch msg := iface.(type) {

			case envoyConnCreatedMsg:
				xdsEnvoyConnections.Inc()
				recv.nodeEnvoys[msg.conn.streamId] = msg.conn

			case envoyConnIdentifiedMsg:
				streams := recv.getSubsetStreams(msg.conn.nodeCluster)
				streams[msg.conn.streamId] = nil

				msg.conn.detailedMetrics = len(streams) <= metrics.EnvoyCardinality()

				msg.conn.saveState(
					resource.ClusterType,
					recv.getSotWSubset(msg.conn.nodeCluster).cds,
				)
				msg.conn.saveState(
					resource.EndpointType,
					recv.getSotWSubset(msg.conn.nodeCluster).eds,
				)
				msg.conn.saveState(
					resource.ListenerType,
					recv.getSotWSubset(msg.conn.nodeCluster).lds,
				)
				msg.conn.saveState(
					resource.RouteType,
					recv.getSotWSubset(msg.conn.nodeCluster).rds,
				)
				msg.conn.saveState(
					resource.SecretType,
					recv.getSotWSubset(msg.conn.nodeCluster).sds,
				)

				close(msg.continueChan)

			case envoyConnDestroyedMsg:
				xdsEnvoyConnections.Dec()
				delete(recv.nodeEnvoys, msg.conn.streamId)

				streams := recv.subsetStreams[msg.conn.nodeCluster]
				delete(streams, msg.conn.streamId)

			case stateChangeMsg:

				switch msg.typeUrl {
				case ClusterType:
					recv.getSotWSubset(msg.subset).cds = msg.resources
				case EndpointType:
					recv.getSotWSubset(msg.subset).eds = msg.resources
				case ListenerType:
					recv.getSotWSubset(msg.subset).lds = msg.resources
				case RouteType:
					recv.getSotWSubset(msg.subset).rds = msg.resources
				case SecretType:
					recv.getSotWSubset(msg.subset).sds = msg.resources
				}

				for streamId := range recv.getSubsetStreams(msg.subset) {
					envoyConn := recv.nodeEnvoys[streamId]
					envoyConn.saveState(msg.typeUrl, msg.resources)
				}
			}
		}
	}
}

func Serve(ctx context.Context, log log15.Logger, xdsInitChan chan<- struct{}, exitChan chan<- uint8,
	syncChan, resetChan <-chan struct{}) {

	if adsServer != nil {
		return
	}

	xdsPort := config.XDSPort()
	log.Info("starting XDS server", "port", xdsPort)

	listener, err := net.Listen("tcp", ":"+strconv.Itoa(xdsPort))
	if err != nil {
		log.Error("net.Listen", "Error", err)
		exitChan <- 1
		close(xdsInitChan)
		return
	}

	if config.Testing() {
		go func() {
			<-ctx.Done()
			adsServer = nil
			listener.Close()
		}()
	}

	adsServer = &adsServerImpl{
		log:           log,
		streamCounter: new(uint64),
		serverChan:    make(chan interface{}, 100),

		nodeEnvoys:    make(map[uint64]*envoyConnection),
		subsetStreams: make(map[EnvoySubset]uniqueStreams),
		sotwSubsets:   make(map[EnvoySubset]*sotw),

		xdsWarnThreshold: config.XDSBacklog() * xdsWarnThresholdPercent / 100,
	}
	go adsServer.loop(ctx, resetChan)
	go adsServer.channelMonitor(ctx)

	close(xdsInitChan)

	// we need StateChange() calls to succeed and store SotW on the ADS server
	//
	// we also need to wait for K8s resources to sync before accepting Envoy
	// connections
	<-syncChan

	grpclogger := &log15GrpcLogger{
		logger:    log,
		verbosity: 99, // https://github.com/grpc/grpc-go#how-to-turn-on-logging
	}
	grpclog.SetLoggerV2(grpclogger)

	if config.GrpcTracing() {
		grpc.EnableTracing = true
	}

	grpcServer := grpc.NewServer([]grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: 10 * time.Minute, // server to client ping
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 30 * time.Second, // commensurate with clusters['kapcom'].http2_protocol_options.connection_keepalive.interval on the envoy side
		}),
		grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
		grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()),
	}...)

	grpcMetrics.InitializeMetrics(grpcServer)

	// Configure health checking
	// a readiness probe can use this since grpc starts after resources are sync-ed
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, adsServer)

	go func() {
		<-ctx.Done()
		log.Info("gRPC server stopping")
		grpcServer.GracefulStop()
	}()

	err = grpcServer.Serve(listener)
	if err != nil && !config.Testing() {
		log.Crit("grpcServer.Serve", "Error", err)
		exitChan <- 1
		return
	}
}

func StateChange(subset EnvoySubset, typeUrl TypeURL, resources set.Set) {
	if adsServer == nil {
		return
	}
	xdsStateChanges.Inc()

	// The values are protected from concurrent access but the map isn't so make
	// a copy. From here on the map is read only while the original resources
	// will continue to have writes/deletions
	resourceKeysCopy := set.New()
	for k, v := range resources {
		resourceKeysCopy[k] = v
	}

	msg := stateChangeMsg{
		subset:    subset,
		typeUrl:   typeUrl,
		resources: resourceKeysCopy,
	}

	xdsServerchanBacklog.Inc()
	select {
	case adsServer.serverChan <- msg:
	default:
		adsServer.log.Warn("channel full")
		adsServer.serverChan <- msg
	}
}
