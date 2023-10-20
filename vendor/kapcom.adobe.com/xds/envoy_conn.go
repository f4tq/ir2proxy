package xds

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/set"
	"kapcom.adobe.com/util"

	"github.com/davecgh/go-spew/spew"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/inconshreveable/log15.v2"
)

type (
	// Use this for testing only
	DiscoveryCallbacks struct {
		Type TypeURL
		Req  func(*discovery.DeltaDiscoveryRequest)
		Res  func(*discovery.DeltaDiscoveryResponse)
	}

	xdsState struct {
		sotw           atomic.Pointer[set.Set]
		sotwVersions   map[string]string
		envoyACKed     set.Set
		envoyNACKed    set.Set
		envoyAddNonces map[uint32]set.Set
		envoyDelNonces map[uint32]set.Set
		nonce          uint32
		envoyACKTimes  map[uint32]time.Time
	}

	envoyConnection struct {
		log         log15.Logger
		streamId    uint64
		nodeId      string
		nodeCluster EnvoySubset

		// these will include both the Envoy identity and xDS TypeUrl which
		// contribute significantly to metric label cardinality
		detailedMetrics bool

		delta     discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
		deltaChan chan *discovery.DeltaDiscoveryRequest

		// communication to the singleton ads server and shared by all envoyConnections
		serverChanSend func(interface{})

		// dedicated channel for the singleton ads server to talk to this envoyConnection
		thisChan chan interface{}

		cds xdsState
		eds xdsState
		lds xdsState
		rds xdsState
		sds xdsState

		// track whether there stale CDS entries in existing Envoys on KAPCOM start
		staleCDS bool
	}
)

var (
	xdsNacks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.ProgramNameLower,
			Subsystem: "xds",
			Name:      "envoy_nacks",
			Help:      "Total number of XDS NACKs.",
		},
		[]string{"xds", "resource"},
	)
	xdsDDRTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: constants.ProgramNameLower,
		Subsystem: "xds",
		Name:      "ddr_times",
		Help:      "xDS time (ms) to handle a DeltaDiscoveryRequest and send a response",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 18), // 1 - 2^17
	}, []string{"envoy", "xds"})
	xdsACKTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: constants.ProgramNameLower,
		Subsystem: "xds",
		Name:      "ack_times",
		Help:      "xDS time (ms) to ACK. This is Envoy processing time plus time on the wire",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 18), // 1 - 2^17
	}, []string{"envoy", "xds"})
)

func init() {
	prometheus.MustRegister(xdsNacks)
	prometheus.MustRegister(xdsDDRTimes)
	prometheus.MustRegister(xdsACKTimes)
}

func newXDSState() xdsState {
	state := xdsState{
		// sotw zero val
		sotwVersions:   make(map[string]string),
		envoyACKed:     set.New(),
		envoyNACKed:    set.New(),
		envoyAddNonces: make(map[uint32]set.Set),
		envoyDelNonces: make(map[uint32]set.Set),
		// nonce zero val
		envoyACKTimes: make(map[uint32]time.Time),
	}
	sotw := set.New()
	state.sotw.Store(&sotw)
	return state
}

func (recv *envoyConnection) saveState(typeUrl TypeURL, resources set.Set) {
	switch typeUrl {
	case ClusterType:
		recv.cds.sotw.Store(&resources)
	case EndpointType:
		recv.eds.sotw.Store(&resources)
	case ListenerType:
		recv.lds.sotw.Store(&resources)
	case RouteType:
		recv.rds.sotw.Store(&resources)
	case SecretType:
		recv.sds.sotw.Store(&resources)
	}

	if recv.generateInternalDDR(typeUrl) {
		select {
		case recv.thisChan <- internalDDRMsg{typeUrl}:
		default:
			recv.log.Error("channel full", "len", len(recv.thisChan))
		}
	}
}

func (recv *envoyConnection) stateChanged(typeUrl TypeURL, sotw *set.Set) (changed bool) {
	switch typeUrl {
	case ClusterType:
		changed = !recv.cds.sotw.CompareAndSwap(sotw, sotw)
	case EndpointType:
		changed = !recv.eds.sotw.CompareAndSwap(sotw, sotw)
	case ListenerType:
		changed = !recv.lds.sotw.CompareAndSwap(sotw, sotw)
	case RouteType:
		changed = !recv.rds.sotw.CompareAndSwap(sotw, sotw)
	case SecretType:
		changed = !recv.sds.sotw.CompareAndSwap(sotw, sotw)
	}
	return
}

func (recv *envoyConnection) generateInternalDDR(typeUrl TypeURL) (answer bool) {
	// don't create DiscoveryResponses if there's a nonce in flight
	// or for no resources
	//
	// saved state will accumulate until we handle the ACK/NACK
	switch typeUrl {
	case ClusterType:
		if len(recv.cds.envoyAddNonces) > 0 || len(recv.cds.envoyDelNonces) > 0 || len(*recv.cds.sotw.Load()) == 0 {
			return
		}

	case EndpointType:
		if len(recv.eds.envoyAddNonces) > 0 || len(recv.eds.envoyDelNonces) > 0 || len(*recv.eds.sotw.Load()) == 0 {
			return
		}

	case ListenerType:
		if len(recv.lds.envoyAddNonces) > 0 || len(recv.lds.envoyDelNonces) > 0 || len(*recv.lds.sotw.Load()) == 0 {
			return
		}

	case RouteType:
		if len(recv.rds.envoyAddNonces) > 0 || len(recv.rds.envoyDelNonces) > 0 || len(*recv.rds.sotw.Load()) == 0 {
			return
		}

	case SecretType:
		if len(recv.sds.envoyAddNonces) > 0 || len(recv.sds.envoyDelNonces) > 0 || len(*recv.sds.sotw.Load()) == 0 {
			return
		}
	}

	answer = true
	return
}

func (recv *envoyConnection) xdsNonce(typeUrl TypeURL, increment bool) (nonce uint32) {
	switch typeUrl {
	case ClusterType:
		if increment {
			recv.cds.nonce++
		}
		nonce = recv.cds.nonce
	case EndpointType:
		if increment {
			recv.eds.nonce++
		}
		nonce = recv.eds.nonce
	case ListenerType:
		if increment {
			recv.lds.nonce++
		}
		nonce = recv.lds.nonce
	case RouteType:
		if increment {
			recv.rds.nonce++
		}
		nonce = recv.rds.nonce
	case SecretType:
		if increment {
			recv.sds.nonce++
		}
		nonce = recv.sds.nonce
	}
	return
}

func (recv *envoyConnection) saveNodeInfo(node *core.Node) {
	// we expect set_node_on_first_message_only to be true
	//
	// protect against the presence of node info on every DiscoveryRequest anyway
	if node == nil || recv.nodeId != "" || recv.nodeCluster != "" {
		return
	}

	recv.nodeId = node.Id
	recv.nodeCluster = EnvoySubset(node.Cluster)
	recv.log = recv.log.New("ni", recv.nodeId, "nc", recv.nodeCluster)
	recv.log.Info("envoy connection identified")
	// synchronously get initial xDS state on the initial DiscoveryRequest
	// so it can be replied to
	//
	// thisChan couldn't be coordinated with deltaChan so there's a race
	// condition in seeding initial xDS state that this approach bypasses
	continueChan := make(chan struct{})
	recv.serverChanSend(envoyConnIdentifiedMsg{recv, continueChan})
	<-continueChan
}

func (recv *envoyConnection) checkNonce(req *discovery.DeltaDiscoveryRequest) (resNonce uint32, ok bool) {
	if req.ResponseNonce == "" || req.ResponseNonce == constants.InternalNonce {
		ok = true
		return
	}

	resNonceUint62, err := strconv.ParseUint(req.ResponseNonce, 10, 32)
	if err != nil {
		recv.log.Error("invalid nonce",
			"ResponseNonce", req.ResponseNonce,
			"Error", err,
			"TypeUrl", req.TypeUrl,
		)
		return
	}

	ok = true
	resNonce = uint32(resNonceUint62)
	return
}

func (recv *envoyConnection) nackResponse(req *discovery.DeltaDiscoveryRequest,
	name string, iface interface{}, envoyNonces map[uint32]set.Set) {

	log := recv.log

	nonce := recv.xdsNonce(TypeURL(req.TypeUrl), true)

	res := &discovery.DeltaDiscoveryResponse{
		TypeUrl: req.TypeUrl,
		Nonce:   fmt.Sprintf("%v", nonce),
	}

	// shared by both envoyAddNonces and envoyDelNonces, use the presence of a
	// resource to infer that we're repeating an attempt to add or remove resources
	if iface == nil {
		res.RemovedResources = []string{name}

		log.Info("reremoving NACKed Resource",
			"name", name, "nonce", nonce, "typeUrl", req.TypeUrl)
	} else {
		var version string
		var protoBytes []byte
		if !iface.(Wrapper).BytesAndVersion(log, &protoBytes, &version) {
			return
		}

		res.Resources = []*discovery.Resource{
			{
				Name:    name,
				Version: version,
				Resource: &any.Any{
					TypeUrl: req.TypeUrl,
					Value:   protoBytes,
				},
			},
		}

		log.Info("resending NACKed Resource",
			"name", name, "nonce", nonce,
			"version", version, "typeUrl", req.TypeUrl)
	}

	// Save these resources for ACK/NACK tracking
	versions := set.New()
	versions[name] = iface
	envoyNonces[nonce] = versions

	if config.Testing() {
		var sotw set.Set

		switch TypeURL(req.TypeUrl) {
		case ClusterType:
			sotw = *recv.cds.sotw.Load()
		case EndpointType:
			sotw = *recv.eds.sotw.Load()
		case ListenerType:
			sotw = *recv.lds.sotw.Load()
		case RouteType:
			sotw = *recv.rds.sotw.Load()
		case SecretType:
			sotw = *recv.sds.sotw.Load()
		}

		if callbacks, ok := sotw[string(recv.nodeCluster)].(DiscoveryCallbacks); ok {
			if callbacks.Res != nil {
				callbacks.Res(res)
			}
		}
	}

	err := recv.delta.Send(res)
	if err != nil {
		log.Error("delta.Send", "Error", err)
	}
}

func (recv *envoyConnection) handleDDR(req *discovery.DeltaDiscoveryRequest) {
	t0 := time.Now()
	reqTypeURL := TypeURL(req.TypeUrl)

	resNonce, ok := recv.checkNonce(req)
	if !ok {
		return
	}

	// don't respond to an internally generated DeltaDiscoveryRequest until
	// Envoy has asked for this TypeUrl
	if req.ResponseNonce == constants.InternalNonce &&
		recv.xdsNonce(reqTypeURL, false) == 0 {
		return
	}

	// must do this before accessing sotw below
	recv.saveNodeInfo(req.Node)

	log := recv.log.New("envoyNonce", req.ResponseNonce, "typeUrl", req.TypeUrl)
	log.Info("DiscoveryRequest",
		"resourceNamesSubscribe", req.ResourceNamesSubscribe,
		"resourceNamesUnsubscribe", req.ResourceNamesUnsubscribe,
		"initialResourceVersions", req.InitialResourceVersions,
	)

	var (
		sotw           *set.Set
		sotwVersions   map[string]string
		envoyACKed     *set.Set // will be assigned to in ACK handling
		envoyNACKed    set.Set
		envoyAddNonces map[uint32]set.Set
		envoyDelNonces map[uint32]set.Set
		envoyACKTimes  map[uint32]time.Time
		addedSet       set.Set
		removedSet     set.Set

		callbacks DiscoveryCallbacks
	)

	switch reqTypeURL {
	case ClusterType:

		sotw = recv.cds.sotw.Load()
		sotwVersions = recv.cds.sotwVersions
		envoyACKed = &recv.cds.envoyACKed
		envoyNACKed = recv.cds.envoyNACKed
		envoyAddNonces = recv.cds.envoyAddNonces
		envoyDelNonces = recv.cds.envoyDelNonces
		envoyACKTimes = recv.cds.envoyACKTimes

	case EndpointType:

		sotw = recv.eds.sotw.Load()
		sotwVersions = recv.eds.sotwVersions
		envoyACKed = &recv.eds.envoyACKed
		envoyNACKed = recv.eds.envoyNACKed
		envoyAddNonces = recv.eds.envoyAddNonces
		envoyDelNonces = recv.eds.envoyDelNonces
		envoyACKTimes = recv.eds.envoyACKTimes

	case ListenerType:

		sotw = recv.lds.sotw.Load()
		sotwVersions = recv.lds.sotwVersions
		envoyACKed = &recv.lds.envoyACKed
		envoyNACKed = recv.lds.envoyNACKed
		envoyAddNonces = recv.lds.envoyAddNonces
		envoyDelNonces = recv.lds.envoyDelNonces
		envoyACKTimes = recv.lds.envoyACKTimes

	case RouteType:

		sotw = recv.rds.sotw.Load()
		sotwVersions = recv.rds.sotwVersions
		envoyACKed = &recv.rds.envoyACKed
		envoyNACKed = recv.rds.envoyNACKed
		envoyAddNonces = recv.rds.envoyAddNonces
		envoyDelNonces = recv.rds.envoyDelNonces
		envoyACKTimes = recv.rds.envoyACKTimes

	case SecretType:

		sotw = recv.sds.sotw.Load()
		sotwVersions = recv.sds.sotwVersions
		envoyACKed = &recv.sds.envoyACKed
		envoyNACKed = recv.sds.envoyNACKed
		envoyAddNonces = recv.sds.envoyAddNonces
		envoyDelNonces = recv.sds.envoyDelNonces
		envoyACKTimes = recv.sds.envoyACKTimes

	default:
		recv.log.Error("unsupported type",
			"envoyNonce", req.ResponseNonce, "typeUrl", req.TypeUrl)
		return
	}

	defer func() {
		// if ACK processing wouldn't call this function again and state changed
		// but we don't know if saveState() is going to be called again we need
		// to respond to the state change
		if recv.generateInternalDDR(reqTypeURL) && recv.stateChanged(reqTypeURL, sotw) {
			select {
			case recv.thisChan <- internalDDRMsg{reqTypeURL}:
				recv.log.Info("generating internalDDRMsg from handleDDR")
			default:
				recv.log.Error("channel full", "len", len(recv.thisChan))
			}
		}
	}()

	// handle ACKs first
	if resNonce > 0 {
		// reuse t0 captured above since not much has happened since
		ackTime := float64(t0.Sub(envoyACKTimes[resNonce]).Milliseconds())
		delete(envoyACKTimes, resNonce)

		if recv.detailedMetrics {
			xdsACKTimes.WithLabelValues(
				recv.nodeId,
				reqTypeURL.XDS(),
			).Observe(ackTime)
		}

		if nonceResources, exists := envoyAddNonces[resNonce]; exists {
			delete(envoyAddNonces, resNonce)

			if req.ErrorDetail == nil {
				*envoyACKed = set.Union(*envoyACKed, nonceResources)

				// if XDS was previously delayed, these acks may allow processing now
				recv.checkDelayedXDS(reqTypeURL, nonceResources)

				for name := range nonceResources {
					log.Info("ACK add/update", "name", name, "time_ms", ackTime)
					delete(envoyNACKed, name)
				}
			} else {
				log.Error("NACK",
					"code", req.ErrorDetail.Code,
					"message", req.ErrorDetail.Message,
					"nonceResources", nonceResources)
				log.Debug("NACK", spew.Sdump(nonceResources))

				for name, iface := range nonceResources {
					xdsNacks.WithLabelValues(reqTypeURL.XDS(), name).Inc()
					iface.(Wrapper).Read(func(msg proto.Message, meta interface{}) {
						switch rsrc := msg.(type) {
						case *listener.Listener:
							for _, fc := range rsrc.FilterChains {
								if fc.FilterChainMatch != nil {
									log.Error("NACKed",
										"name", name,
										"server_names", fc.FilterChainMatch.ServerNames)
								}
							}
						}
					})
				}

				if len(nonceResources) > 1 {
					for name, iface := range nonceResources {
						recv.nackResponse(req, name, iface, envoyAddNonces)
					}
				} else {
					// we've identified a single resource that is NACKed
					//
					// hold it in NACK tracking until something changes
					for name, iface := range nonceResources {
						envoyNACKed[name] = iface
					}
				}
			}
		} else if nonceResources, exists := envoyDelNonces[resNonce]; exists {
			delete(envoyDelNonces, resNonce)

			if req.ErrorDetail == nil {
				*envoyACKed = set.Difference(*envoyACKed, nonceResources)
				for name := range nonceResources {
					log.Info("ACK remove", "name", name)
					delete(envoyNACKed, name)
				}
			} else {
				log.Error("NACK",
					"code", req.ErrorDetail.Code,
					"message", req.ErrorDetail.Message,
					"nonceResources", nonceResources)

				if len(nonceResources) > 1 {
					for name, iface := range nonceResources {
						recv.nackResponse(req, name, iface, envoyDelNonces)
					}
				} else {
					// we've identified a single resource that is NACKed
					//
					// hold it in NACK tracking until something changes
					for name, iface := range nonceResources {
						envoyNACKed[name] = iface
					}
				}
			}
		} else {
			log.Error("missing nonce. breaking connection")
			recv.thisChan <- shutdownMsg{missingNonce}
			log.Error("sent shutdown signal")
		}
	}

	// For testing we'd like to know what's being received and sent so we
	// embed funcs in SotW to be called. Since SotW is shared by all Envoys
	// we separate them by their nodeCluster
	if config.Testing() {
		if callbacks, ok = (*sotw)[string(recv.nodeCluster)].(DiscoveryCallbacks); ok {
			delete(*sotw, string(recv.nodeCluster))
			defer func() {
				(*sotw)[string(recv.nodeCluster)] = callbacks
			}()

			if callbacks.Req != nil {
				callbacks.Req(req)
			}
		}
	}

	nonce := recv.xdsNonce(reqTypeURL, true)

	// If Envoy requests previously ACKed resources, they must be resent
	// This would happen when KAPCOM eagerly sends new/updated resources without being asked for them
	// https://www.envoyproxy.io/docs/envoy/v1.24.8/api-docs/xds_protocol#how-the-client-specifies-what-resources-to-return
	//   When the client sends a new request that changes the set of resources being requested,
	//   the server must resend any newly requested resources, even if it previously sent those
	//   resources without having been asked for them and the resources have not changed since that time.
	for _, sub := range req.ResourceNamesSubscribe {
		if _, exists := (*envoyACKed)[sub]; exists {
			log.Info("resend of previously ACKed resource", "name", sub)
			delete(*envoyACKed, sub)
		}
	}

	// the set of resources to add are all those in the SotW minus all ACKed
	// resources
	addedSet = set.Difference(*sotw, *envoyACKed)
	// minus all NACKed resources we know Envoy will just reject again
	//
	// NACKed resources that have changed will be put back into the addedSet
	addedSet = set.Difference(addedSet, envoyNACKed)

	log = log.New("nextNonce", nonce)

	if config.DebugLogs() {
		for key := range addedSet {
			log.Debug("addedSet", "name", key)
		}
	}

	// The above only accounts for new resources
	//
	// We also need to send updated ones
	for name, iface := range *sotw {
		versionsMatch := sotwVersions[name] == iface.(Wrapper).Version(log)
		if _, exists := addedSet[name]; !exists && !versionsMatch {
			log.Debug("resource changed", "name", name)
			addedSet[name] = iface

			// if something changed we assume it changed for the better and
			// start NACK tracking over again
			delete(envoyNACKed, name)
		}
	}

	// But not if Envoy already knows about these resources and the versions match.
	// These are also considered previously ACKed (except in the case of EDS)
	// initialResourceVersionsLoop:
	for name, version := range req.InitialResourceVersions {
		if version == "" {
			log.Warn("missing version in InitialResourceVersions", "name", name)
		}

		if wrapper := addedSet[name]; wrapper != nil {
			/*if wrapper.(Wrapper).Version(log) == version {

				// Send EDS to Envoys with existing EDS of the same version
				// because CDS may have changed but won't associate existing EDS
				// with it
				//
				// We can look at the addNonces because CDS won't ACK until it's
				// warmed
				//
				// references:
				// https://github.com/envoyproxy/envoy/issues/22418
				// https://github.com/envoyproxy/envoy/issues/13009
				// https://git.corp.adobe.com/adobe-platform/kapcom/issues/287
				// ./cds_warming.md
				if reqTypeURL == EndpointType {
					for _, addNonce := range recv.cds.envoyAddNonces {
						if _, exists := addNonce[name]; exists {
							continue initialResourceVersionsLoop
						}
					}
				}

				delete(addedSet, name)

				(*envoyACKed)[name] = wrapper
				sotwVersions[name] = version
				log.Debug("removing initial resource version", "name", name)
			}*/
		} else {
			// If this is a resource name that doesn't exist in the current SotW
			// it still needs to be added as a previously ACKed resource so it
			// can be removed
			if _, exists := (*envoyACKed)[name]; !exists {
				log.Warn("unknown but previously ACKed resource", "name", name)
				(*envoyACKed)[name] = nil
				recv.staleCDS = recv.staleCDS || reqTypeURL == ClusterType || reqTypeURL == EndpointType
			}
		}
	}

	// the set of resources to remove are all those previously ACKed minus the
	// current SotW
	removedSet = set.Difference(*envoyACKed, *sotw)
	// minus all NACKed resources we know Envoy will just reject again
	removedSet = set.Difference(removedSet, envoyNACKed)

	// Also not if they're part of an in-flight DeltaDiscoveryResponse for which
	// we're waiting on an ACK
	//
	// It's noteworthy that this creates a backpressure mechanism for aggregate
	// (LDS, RDS) as well as granular (CDS, EDS, SDS) resources. The content
	// (i.e. Version()) is not checked, only the name. All of xDS can change
	// multiple times without causing spurious Envoy updates
	// (e.g. v2, v3, v4 while v1 is still being processed - only v4 is sent)
	for _, inflightResources := range envoyAddNonces {
		for name := range inflightResources {
			if _, exists := addedSet[name]; exists {
				log.Debug("removing in-flight resource", "name", name)
				delete(addedSet, name)
			}
		}
	}

	for _, inflightResources := range envoyDelNonces {
		for name := range inflightResources {
			if _, exists := removedSet[name]; exists {
				log.Debug("removing in-flight resource", "name", name)
				delete(removedSet, name)
			}
		}
	}

	// check special cases that may require to delay CDS
	recv.delayXDS(reqTypeURL, addedSet, removedSet)

	res := &discovery.DeltaDiscoveryResponse{
		TypeUrl: req.TypeUrl,
		Nonce:   fmt.Sprintf("%v", nonce),
	}

	// separate added resources from removed resources to simplify NACK handling
	if len(addedSet) > 0 {

		addedVersions := set.New()

		// all created and updated resources
		res.Resources = make([]*discovery.Resource, 0, len(addedSet))
		for name, iface := range addedSet {
			var version string
			var protoBytes []byte
			if !iface.(Wrapper).BytesAndVersion(log, &protoBytes, &version) {
				continue
			}

			sotwVersions[name] = version
			addedVersions[name] = iface

			res.Resources = append(res.Resources, &discovery.Resource{
				Name:    name,
				Version: version,
				Resource: &any.Any{
					TypeUrl: req.TypeUrl,
					Value:   protoBytes,
				},
			})
			log.Info("sending Resource", "name", name, "version", version)
		}

		// Save these resources for ACK/NACK tracking
		envoyAddNonces[nonce] = addedVersions
	} else if len(removedSet) > 0 {

		removedVersions := set.New()

		res.RemovedResources = make([]string, 0, len(removedSet))
		for name := range removedSet {
			removedVersions[name] = nil // Envoy doesn't need the content, just the name
			delete(sotwVersions, name)
			res.RemovedResources = append(res.RemovedResources, name)
			log.Info("removing Resource", "name", name)
		}

		// Save these resources for ACK/NACK tracking
		envoyDelNonces[nonce] = removedVersions
	} else {
		// No CRUD means no response
		log.Debug("ignoring DiscoveryRequest")
		// if Envoy loses interest in resources that are in SotW, we need to untrack them
		// so they can be resent if it regains interest later
		for _, unsub := range req.ResourceNamesUnsubscribe {
			if _, exists := (*sotw)[unsub]; exists {
				log.Info("untracking known resource due to Envoy unsubscribing", "name", unsub)
				delete(*envoyACKed, unsub)
			}
		}
		return
	}

	if callbacks.Res != nil {
		callbacks.Res(res)
	}

	var err error
	duration := util.Profile(func() {
		err = recv.delta.Send(res)
	})
	if err != nil {
		log.Error("delta.Send", "Error", err)
	}

	log.Info("delta.Send",
		"Resources", len(res.Resources),
		"RemovedResources", len(res.RemovedResources),
		"time_ms", duration.Milliseconds())

	t1 := time.Now()
	envoyACKTimes[nonce] = t1

	if recv.detailedMetrics {
		// only sample when we've sent something
		xdsDDRTimes.WithLabelValues(
			recv.nodeId,
			reqTypeURL.XDS(),
		).Observe(float64(t1.Sub(t0).Milliseconds()))
	}
}

func (recv *envoyConnection) run() {
	go recv.xdsHandler()

	nonceTimer := time.NewTimer(0)
	nonceInFlightOccurrences := 0

	for {
		select {
		case <-recv.delta.Context().Done():
			return

		case <-nonceTimer.C:
			nonceTimer.Reset(5 * time.Second)

			anyNonceInFlight := false
			for key := range recv.cds.envoyAddNonces {
				recv.log.Info("CDS nonce in flight", "nonce", key)
				anyNonceInFlight = true
			}
			for key := range recv.eds.envoyAddNonces {
				recv.log.Info("EDS nonce in flight", "nonce", key)
				anyNonceInFlight = true
			}
			for key := range recv.lds.envoyAddNonces {
				recv.log.Info("LDS nonce in flight", "nonce", key)
				anyNonceInFlight = true
			}
			for key := range recv.rds.envoyAddNonces {
				recv.log.Info("RDS nonce in flight", "nonce", key)
				anyNonceInFlight = true
			}
			for key := range recv.sds.envoyAddNonces {
				recv.log.Info("SDS nonce in flight", "nonce", key)
				anyNonceInFlight = true
			}

			if anyNonceInFlight {
				nonceInFlightOccurrences++
			} else {
				nonceInFlightOccurrences = 0
			}

			// after 10 minutes, rather than try to re-send un-ACKed resources
			// simply shutdown the connection and allow initial resource version
			// logic to produce the same result but with greater confidence
			if nonceInFlightOccurrences > 120 {
				recv.log.Warn("assuming a network partition and shutting down")
				return
			}

		case req := <-recv.deltaChan:
			recv.handleDDR(req)

		case iface := <-recv.thisChan:
			switch msg := iface.(type) {

			case shutdownMsg:
				recv.log.Info("received shutdown signal", "reason", msg.reason)
				return

			case internalDDRMsg:
				recv.handleDDR(&discovery.DeltaDiscoveryRequest{
					TypeUrl:       string(msg.typeUrl),
					ResponseNonce: constants.InternalNonce,
				})
			}
		}
	}
}

func (recv *envoyConnection) xdsHandler() {
	for {
		req, err := recv.delta.Recv()
		if err == nil {
			recv.deltaChan <- req
		} else {
			recv.log.Error("delta.Recv", "Error", err)
		}

		// we assume Context errors are a subset of errors that delta.Recv()
		// produce which is why we log its err but only return on Context.Err()
		if recv.delta.Context().Err() != nil {
			return
		}
	}
}
