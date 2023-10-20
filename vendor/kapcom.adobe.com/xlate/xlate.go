// package xlate translates between K8s CRDs and XDS protobufs
package xlate

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/constants/annotations"
	crds "kapcom.adobe.com/crds/v1"
	"kapcom.adobe.com/set"
	"kapcom.adobe.com/types"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xds"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/golang/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/inconshreveable/log15.v2"
	k8s "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type EnvoyRole int

const (
	GatewayRole EnvoyRole = iota + 1
	SidecarRole
)

const doTriggerXDS bool = true

type (
	addEvent struct {
		iface interface{}
	}

	updateEvent struct {
		old interface{}
		new interface{}
	}

	deleteEvent struct {
		iface interface{}
	}

	httpEvent struct {
		responseChan chan SotWResponse
	}

	mTLS struct {
		caSecrets []*k8s.Secret
		caCerts   *tls.CommonTlsContext_ValidationContext

		clientSecret *k8s.Secret
		serverSecret *k8s.Secret
	}

	SotW struct {
		subset xds.EnvoySubset
		role   EnvoyRole

		// SotWs are created by types that represent them, or xds.DefaultEnvoySubset
		//
		// Currently the only type that represents a SotW is the Sidecar. Since
		// multiple Sidecars with different settings can reference the same
		// Ingress we need know which Sidecar created this SotW
		sidecar *crds.Sidecar

		cds set.Set
		eds set.Set
		lds set.Set
		rds set.Set
		sds set.Set
	}

	CRDHandler struct {
		log              log15.Logger
		events           chan interface{}
		updateSotW       func(xds.EnvoySubset, xds.TypeURL, set.Set)
		namespaces       map[string]namespaceCRDs
		secrets          map[string]*k8s.Secret
		mtls             mTLS
		tlsDelegations   map[string]TLSCertificateDelegation
		envoySubsets     map[xds.EnvoySubset]SotW
		statusHandler    *statusHandler
		lc               *ListenerConfig
		statsListener    xds.Wrapper
		statsCluster     xds.Wrapper
		rateLimitCluster xds.Wrapper
		authzCluster     xds.Wrapper
		migrated         map[*Ingress]struct{}

		// given the options about how to store IP address association with zone
		// we choose to expand a CIDR into IP addresses it covers and store
		// them compactly as a map of uint32 (4 bytes vs 15) to string knowing
		// that the zone string is not much bigger than a pointer (i.e. pointer
		// to string) and that we want fast lookups when forming
		// ClusterLoadAssignment's Endpoints
		ip2zone map[uint32]string

		// We can solve any problem by introducing an extra level of indirection
		// — David Wheeler
		//
		// Services and Endpoints have the same name and can be referenced by
		// multiple Ingresses across namespaces via delegation. This is a
		// reverse lookup to more efficiently process CRD updates into
		// corresponding XDS
		//
		// Updates to Ingresses are problematic when doing Service to Ingress
		// tracking. An update is a new pointer to the updated Ingress. If we
		// had weak pointers this wouldn't be a problem. Every time we traversed
		// cluster2ingress we'd check if the pointer was still referenced,
		// ensuring that only the most recent (i.e. older ones would have a ref
		// count of 0) Ingress pointer is used
		//
		// Instead we have a "stable" pointer (the first) which gets
		// updated by changing its value, the second pointer.
		// The stable pointer is shared by the value of ingressMap
		//
		// This requires a bit more maintenance but is better than the
		// alternatives
		cluster2ingress map[string][]**Ingress
	}
)

var (
	statusUpdateHandler *statusHandler

	xlateEventsBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: constants.ProgramNameLower,
		Subsystem: "xlate",
		Name:      "events_backlog",
		Help:      "Current CRD xlate events backlog.",
	})

	ipv4CIDRRE = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)`)
)

func init() {
	prometheus.MustRegister(xlateEventsBacklog)
}

func Start(ctx context.Context, log log15.Logger,
	updateSotW func(xds.EnvoySubset, xds.TypeURL, set.Set),
	exitChan chan<- uint8,
	syncChan chan<- struct{},
) *CRDHandler {
	if statusUpdateHandler == nil {
		statusUpdateHandler = createStatusHandler(ctx, log)
	}

	handler := &CRDHandler{
		log:        log,
		events:     make(chan interface{}, 100000), // don't create backpressure on the Informers
		updateSotW: updateSotW,
		namespaces: make(map[string]namespaceCRDs),
		secrets:    make(map[string]*k8s.Secret),
		// mtls zero-val
		tlsDelegations: make(map[string]TLSCertificateDelegation),
		envoySubsets:   make(map[xds.EnvoySubset]SotW),
		statusHandler:  statusUpdateHandler,
		lc:             new(ListenerConfig),
		// statsListener set in initStatsListener
		// statsCluster set in initStatsCluster
		migrated:        make(map[*Ingress]struct{}),
		ip2zone:         make(map[uint32]string),
		cluster2ingress: make(map[string][]**Ingress),
	}
	handler.addSotW(xds.DefaultEnvoySubset, GatewayRole, nil)

	if !LoadListenerConfig(log, handler.lc) {
		exitChan <- 1
		return nil
	}

	if handler.lc.Stats.StatsPort != 0 {
		handler.initStatsCluster()
		handler.initStatsListener()
	}
	if RateLimitEnabled() {
		handler.initRatelimitCluster()
	}
	if AuthzEnabled() {
		handler.initAuthzCluster()
	}
	go handler.loop(ctx, exitChan, syncChan)
	go handler.channelMonitor(ctx, exitChan)

	return handler
}

func TestStart(ctx context.Context, log log15.Logger,
	updateSotW func(xds.EnvoySubset, xds.TypeURL, set.Set),
) *CRDHandler {
	return Start(ctx, log, updateSotW, make(chan uint8), make(chan struct{}))
}

func RegisterStatusUpdateFunc(name string, updFunc statusUpdateFunc) {
	statusUpdateHandler.registerUpdaterFunc(name, updFunc)
}

func SecretsKey(secret *k8s.Secret) string {
	return secret.Namespace + constants.SecretsDelimiter + secret.Name
}

func serviceKey(ns, name string) string {
	return ns + "/" + name
}

// Subsets consist of types that represent them, or xds.DefaultEnvoySubset
//
// Currently the only type that represents a xds.EnvoySubset is the Sidecar
func subsetsKey(iface interface{}) xds.EnvoySubset {
	var key string

	switch t := iface.(type) {
	case *crds.Sidecar:
		key = strings.Join([]string{
			crds.ApiGroup,
			crds.ApiVersion,
			crds.SidecarKind,
			t.Namespace,
			t.Name,
		}, "/")
	default: // includes nil
		return xds.DefaultEnvoySubset
	}

	return xds.EnvoySubset(key)
}

func tlsDelegationKey(tlsDelegation TLSCertificateDelegation) string {
	return tlsDelegation.Namespace_() + "/" + tlsDelegation.Name_()
}

func tlsDelegationMap(tlsDelegation TLSCertificateDelegation) map[string]map[string]struct{} {
	delegationMap := make(map[string]map[string]struct{})
	for _, deleg := range tlsDelegation.Delegations() {
		secret := tlsDelegation.Namespace_() + constants.SecretsDelimiter + deleg.SecretName()
		if delegationMap[secret] == nil {
			delegationMap[secret] = make(map[string]struct{})
		}
		for _, ns := range deleg.TargetNamespaces() {
			delegationMap[secret][ns] = struct{}{}
		}
	}
	return delegationMap
}

func (recv *CRDHandler) OnAdd(iface interface{}) {
	xlateEventsBacklog.Inc()
	recv.events <- addEvent{iface}
}

func (recv *CRDHandler) OnUpdate(old, new interface{}) {
	xlateEventsBacklog.Inc()
	recv.events <- updateEvent{old, new}
}

func (recv *CRDHandler) OnDelete(iface interface{}) {
	xlateEventsBacklog.Inc()
	recv.events <- deleteEvent{iface}
}

func (recv *CRDHandler) Register(callback chan SotWResponse) {
	recv.events <- httpEvent{callback}
}

func (recv *CRDHandler) InCharge() types.InChargeAnswer {
	svcNs := config.KAPCOMNamespace()
	svcName := config.KAPCOMServiceName()
	if kapcomEndpoints, exists := recv.getNS(svcNs).endpoints[svcName]; exists {
		var maxIP uint32
		for _, subset := range kapcomEndpoints.Subsets {
			// K8s may think we're not ready, but we can still be in charge (or not)!
			for _, address := range append(subset.Addresses, subset.NotReadyAddresses...) {
				if ip := net.ParseIP(address.IP); ip != nil {
					if dec := util.IP2Uint32(ip); dec > maxIP {
						maxIP = dec
					}
				}
			}
		}
		if config.PodIPUint32() >= maxIP {
			return types.Yes
		} else {
			return types.No
		}
	}

	recv.log.Warn("No kapcom endpoints discovered yet")
	return types.Unknown
}

func (recv *CRDHandler) getNS(ns string) namespaceCRDs {
	if nss, exists := recv.namespaces[ns]; exists {
		return nss
	}

	nss := newNamespaceCRDs()
	recv.namespaces[ns] = nss
	return nss
}

// mapIngresses takes a func that maps over all the known Ingresses and returns
// true if mapping should stop
func (recv *CRDHandler) mapIngresses(mapFunc func(*Ingress) bool) {
	for _, nsCRDs := range recv.namespaces {
		for _, iMap := range nsCRDs.ingressTypes {
			for _, iPtr := range iMap {
				if mapFunc(*iPtr) {
					return
				}
			}
		}
	}
}

func (recv *CRDHandler) addCluster2Ingress(ingress *Ingress) {
	iPtr := recv.getNS(ingress.Namespace).getIngressPtr(ingress)
	if iPtr == nil {
		recv.log.Error("iPtr == nil")
		return
	}

	handleCluster := func(cluster Cluster, ns string) {
		var referenced bool

		// for delegated Routes and delegated TCPProxy we must use the delegate's route's or TCPProxy namespace
		if ns == "" {
			ns = ingress.Namespace
		}
		svcKey := serviceKey(ns, cluster.Name)

		if _, exists := recv.cluster2ingress[svcKey]; !exists {
			recv.cluster2ingress[svcKey] = []**Ingress{}
		}

		for _, iPtr2 := range recv.cluster2ingress[svcKey] {
			if iPtr == iPtr2 {
				referenced = true
				break
			}
		}

		if !referenced {
			recv.log.Debug("added cluster2ingress",
				"svcKey", svcKey, "ns", (*iPtr).Namespace, "name", (*iPtr).Name)
			recv.cluster2ingress[svcKey] = append(recv.cluster2ingress[svcKey], iPtr)
		}
	}

	switch tcpProxy := ingress.Listener.ResolvedTCPProxy(); tcpProxy {
	case nil:
		for _, route := range ingress.VirtualHost.ResolvedRoutes() {
			for _, cluster := range route.Clusters {
				handleCluster(cluster, route.namespace)
			}
		}
	default:
		for _, cluster := range tcpProxy.Clusters {
			handleCluster(cluster, tcpProxy.namespace)
		}
	}
}

func (recv *CRDHandler) deleteCluster2Ingress(ingress *Ingress) {
	iPtr := recv.getNS(ingress.Namespace).getIngressPtr(ingress)
	if iPtr == nil {
		recv.log.Error("iPtr == nil")
		return
	}

	for svcKey, iPtrList := range recv.cluster2ingress {
		var (
			foundIngress bool
			i            int
			iPtr2        **Ingress
		)

		for i, iPtr2 = range iPtrList {
			if iPtr == iPtr2 {
				foundIngress = true
				break
			}
		}

		if foundIngress {
			iPtrList = append(iPtrList[:i], iPtrList[i+1:]...)
			if len(iPtrList) > 0 {
				recv.cluster2ingress[svcKey] = iPtrList
			} else {
				delete(recv.cluster2ingress, svcKey)
			}
		}
	}
}

// TODO(bcook) `type SotWSubset interface` as input
func (recv *CRDHandler) addSotW(subset xds.EnvoySubset, role EnvoyRole, iface interface{}) {
	var sotw SotW
	var exists bool

	if sotw, exists = recv.envoySubsets[subset]; !exists {
		sotw = SotW{
			subset: subset,
			role:   role,

			cds: set.New(),
			eds: set.New(),
			lds: set.New(),
			rds: set.New(),
			sds: set.New(),
		}
	}

	switch t := iface.(type) {
	case *crds.Sidecar:
		sotw.sidecar = t
	}

	recv.envoySubsets[subset] = sotw
}

func (recv *CRDHandler) deleteSotW(subset xds.EnvoySubset) {
	if subset == xds.DefaultEnvoySubset {
		recv.log.Error("deleteSotW called on default subset")
		return
	}
	delete(recv.envoySubsets, subset)
}

func (recv *CRDHandler) getSotWs(ingress *Ingress) []SotW {
	sotws := []SotW{
		recv.envoySubsets[xds.DefaultEnvoySubset],
	}

	for _, sidecar := range recv.getNS(ingress.Namespace).sidecars {
		if sidecar.Spec.Ingress.TypeURL == ingress.TypeURL &&
			sidecar.Spec.Ingress.Name == ingress.Name {

			sotws = append(sotws, recv.envoySubsets[subsetsKey(sidecar)])
		}
	}
	return sotws
}

// given an Ingress or Service, or Endpoint, find the corresponding
// Ingresses that are affected
// low priority Ingresses cannot be "affected" and are filtered out
func (recv *CRDHandler) getIngressList(ns, crdName string) []*Ingress {
	iList := []*Ingress{}

	for _, iMap := range recv.getNS(ns).ingressTypes {
		if iPtr := iMap[crdName]; iPtr != nil {
			if recv.isHighestPriorityIngress(*iPtr) {
				iList = append(iList, *iPtr)
			}
		}
	}

	for _, iPtr := range recv.cluster2ingress[serviceKey(ns, crdName)] {
		if recv.isHighestPriorityIngress(*iPtr) {
			iList = append(iList, *iPtr)
		}
	}

	return iList
}

func (recv *CRDHandler) sidecarIngress(sidecar *crds.Sidecar) *Ingress {
	iMap := recv.getNS(sidecar.Namespace).ingressTypes[sidecar.Spec.Ingress.TypeURL]
	if iMap == nil {
		return nil
	}

	iPtr := iMap[sidecar.Spec.Ingress.Name]
	if iPtr == nil {
		return nil
	}

	return *iPtr
}

func (recv *CRDHandler) cleanupFailedDelegations(ingress *Ingress) {
	for _, nsCRDs := range recv.namespaces {
		for delegate, iPtrList := range nsCRDs.failedDelegations {
			var (
				foundIngress bool
				i            int
				iPtr         **Ingress
			)

			for i, iPtr = range iPtrList {
				if *iPtr == ingress {
					foundIngress = true
					break
				}
			}

			if foundIngress {
				iPtrList = append(iPtrList[:i], iPtrList[i+1:]...)
				if len(iPtrList) > 0 {
					nsCRDs.failedDelegations[delegate] = iPtrList
				} else {
					delete(nsCRDs.failedDelegations, delegate)
				}
			}
		}
	}
}

// Rather than maintain a DAG we resolve the delegations by storing delegated
// Routes now. The simplifies the rest of the code which can effectively ignore
// the concept of delegation
//
// Failed delegations need to tracked so updates to the delegates cause
// delegators to re-resolve
func (recv *CRDHandler) resolveRouteDelegations(ingressOriginal *Ingress) {
	if !ingressOriginal.Valid() {
		return
	}

	// map of delegate namespace to delegate failures by name
	//
	// only the node in the DAG causing the failure needs to be stored
	failedDelegations := make(map[string][]string)

	// this gets reset for each resolution loop so we don't keep stale entries
	// when Ingress Delegator or Delegate change
	ingressOriginal.VirtualHost.delegateRoutes = make(map[*Route]interface{})

	// we must not delegate to paths we also defined
	nonDelegatedRoutes := make(map[string]interface{})
	for _, route := range ingressOriginal.VirtualHost.Routes {
		if route.Delegate == nil {
			nonDelegatedRoutes[route.Match] = nil
		}
	}

	ingress := ingressOriginal

routesLoop:
	for _, route := range ingressOriginal.VirtualHost.Routes {
		if route.Delegate == nil {
			// this may be a Route that's delegated to and its pointer stored
			// in another VirtualHosts's delegateRoutes
			//
			// in any case it's the Route's namespace that's use to get namespaceCRDs
			route.namespace = ingressOriginal.Namespace
			continue
		}

		delegate := route.Delegate
		delegatesChain := DelegatesChain{}
		delegatesChain.Append(delegate)

	delegateResolutionLoop:
		for {
			ns := delegate.Namespace
			if ns == "" {
				ns = ingress.Namespace
			}

			iMap := recv.getNS(ns).ingressTypes[ingressOriginal.TypeURL]
			if iMap == nil {
				recv.log.Warn("delegation failed",
					"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
					"delegate_ns", ns, "delegate_name", delegate.Name,
					"route_match", route.Match, "reason", "delegate does not exist")
				failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
				route.delegationFailed = true
				continue routesLoop
			}

			ingressNext := iMap[delegate.Name]
			if ingressNext == nil {
				recv.log.Warn("delegation failed",
					"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
					"delegate_ns", ns, "delegate_name", delegate.Name,
					"route_match", route.Match, "reason", "delegate does not exist",
				)
				failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
				route.delegationFailed = true
				continue routesLoop
			}

			if !recv.delegateAuthValid(ingress, *ingressNext) {
				recv.log.Warn("delegation failed",
					"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
					"delegate_ns", ns, "delegate_name", delegate.Name,
					"route_match", route.Match, "reason", "delegate requires auth",
				)
				recv.getNS(ns).addFailedDelegation(
					recv.log, delegate.Name,
					recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
				)
				ingress.SetInvalid("delegate requires auth")
				return
			}

			if !(*ingressNext).Valid() {
				recv.log.Warn("delegation failed",
					"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
					"delegate_ns", ns, "delegate_name", delegate.Name,
					"route_match", route.Match, "reason", "delegate is invalid",
				)
				failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
				route.delegationFailed = true
				continue routesLoop
			}

			if *ingressNext == ingressOriginal {
				recv.log.Warn("delegation cycle",
					"ns", (*ingressNext).Namespace, "name", (*ingressNext).Name, "route", route.Match)
				ingress.SetInvalid("delegation cycle")
				return
			}

			if delegatesChain.Inherits() && (*ingressNext).Fqdn != "" {
				recv.log.Warn("delegate defines a FQDN",
					"ns", (*ingressNext).Namespace, "name", (*ingressNext).Name, "route", route.Match, "FQDN", (*ingressNext).Fqdn)
				ingress.SetInvalid("delegate defines a FQDN")
				return
			}

			anyRoutesMatched := false
			for _, routeToMatch := range (*ingressNext).VirtualHost.Routes {
				if _, exists := nonDelegatedRoutes[routeToMatch.Match]; exists {
					continue
				}

				if delegate.Inherit {
					// do not try to match the prefix when using HTTPProxy's "includes"
					anyRoutesMatched = true
				} else {
					// the route we're delegating (e.g. /a) must be part of the
					// delegate path which may be more specific (e.g. /a or /a/b)
					if !strings.HasPrefix(routeToMatch.Match, route.Match) {
						continue
					}
					anyRoutesMatched = true
				}

				if routeToMatch.Delegate != nil {
					// assume success and remove tracking
					recv.getNS(ns).deleteFailedDelegation(
						recv.log, delegate.Name,
						recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
					)

					// save the delegate in the chain before moving on to the next ingress
					delegatesChain.Append(routeToMatch.Delegate)

					// before reassigning delegate and ingress
					ingress = *ingressNext
					delegate = routeToMatch.Delegate

					continue delegateResolutionLoop
				}

				// save the chain of delegations that can lead to this ingress
				routeToMatch.SaveDelegatesChain(ingressOriginal, delegatesChain)

				recv.log.Info("route delegated",
					"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
					"delegate_ns", (*ingressNext).Namespace, "delegate_name", (*ingressNext).Name,
					"delegator_match", route.Match, "delegate_match", routeToMatch.Match,
				)

				// mark any previous failures as success
				route.delegationFailed = false

				// remove tracking
				recv.getNS(ns).deleteFailedDelegation(
					recv.log, delegate.Name,
					recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
				)

				// store the Route pointer
				ingressOriginal.VirtualHost.delegateRoutes[routeToMatch] = nil

				recv.log.Debug("delegate route", "routeToMatch", routeToMatch)
			}

			if anyRoutesMatched {
				continue routesLoop
			}

			recv.log.Warn("delegate is missing a route",
				"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
				"delegate_ns", (*ingressNext).Namespace, "delegate_name", (*ingressNext).Name,
				"route_match", route.Match,
			)
			failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
			route.delegationFailed = true
			continue routesLoop
		}
	}

	for ns, delegates := range failedDelegations {
		for _, delegate := range delegates {
			recv.getNS(ns).addFailedDelegation(
				recv.log, delegate,
				recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
			)
		}
	}
}

// Rather than maintain a DAG we resolve the delegation by storing delegated
// TCPProxy now. The simplifies the rest of the code which can effectively ignore
// the concept of delegation
//
// Failed delegation needs to be tracked so updates to the delegates cause
// delegators to re-resolve
func (recv *CRDHandler) resolveTCPProxyDelegation(ingressOriginal *Ingress) {
	if !ingressOriginal.Valid() {
		return
	}

	// map of delegate namespace to delegate failures by name
	//
	// only the node in the DAG causing the failure needs to be stored
	failedDelegations := make(map[string][]string)

	// this gets reset for each resolution loop so we don't keep stale entries
	// when Ingress Delegator or Delegate change
	ingressOriginal.Listener.delegateTCPProxy = nil

	// If the following conditions hold, the TCPProxy is non-delegated
	// and we are done (just make sure the proper values are populated
	// for the namespace, so that the TCPProxy is correctly programmed)
	if ingressOriginal.Listener.TCPProxy == nil {
		return
	}
	if ingressOriginal.Listener.TCPProxy.Delegate == nil {
		ingressOriginal.Listener.TCPProxy.namespace = ingressOriginal.Namespace
		return
	}

	ingress := ingressOriginal

	delegate := ingressOriginal.Listener.TCPProxy.Delegate

	for {
		ns := delegate.Namespace
		if ns == "" {
			ns = ingress.Namespace
		}

		iMap := recv.getNS(ns).ingressTypes[ingressOriginal.TypeURL]
		if iMap == nil {
			recv.log.Warn("TCPProxy delegation failed",
				"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
				"delegate_ns", ns, "delegate_name", delegate.Name,
				"reason", "delegate does not exist")
			failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
			ingressOriginal.Listener.TCPProxy.delegationFailed = true
			break
		}

		ingressNext := iMap[delegate.Name]
		if ingressNext == nil {
			recv.log.Warn("TCPProxy delegation failed",
				"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
				"delegate_ns", ns, "delegate_name", delegate.Name,
				"reason", "delegate does not exist",
			)
			failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
			ingressOriginal.Listener.TCPProxy.delegationFailed = true
			break
		}

		if !(*ingressNext).Valid() {
			recv.log.Warn("TCPProxy delegation failed",
				"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
				"delegate_ns", ns, "delegate_name", delegate.Name,
				"reason", "delegate is invalid",
			)
			failedDelegations[ns] = append(failedDelegations[ns], delegate.Name)
			ingressOriginal.Listener.TCPProxy.delegationFailed = true
			break
		}

		if *ingressNext == ingressOriginal {
			recv.log.Warn("TCPProxy delegation cycle",
				"ns", (*ingressNext).Namespace, "name", (*ingressNext).Name)
			ingress.SetInvalid("delegation cycle")
			return
		}

		tcpProxyToDelegate := (*ingressNext).Listener.TCPProxy

		if tcpProxyToDelegate.Delegate != nil {
			// assume success and remove tracking
			recv.getNS(ns).deleteFailedDelegation(
				recv.log, delegate.Name,
				recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
			)

			// before reassigning delegate and ingress
			ingress = *ingressNext
			delegate = tcpProxyToDelegate.Delegate
			continue
		}

		recv.log.Info("TCPProxy delegated",
			"delegator_ns", ingressOriginal.Namespace, "delegator_name", ingressOriginal.Name,
			"delegate_ns", (*ingressNext).Namespace, "delegate_name", (*ingressNext).Name,
		)

		// mark any previous failures as success
		ingressOriginal.Listener.TCPProxy.delegationFailed = false

		// remove tracking
		recv.getNS(ns).deleteFailedDelegation(
			recv.log, delegate.Name,
			recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
		)

		// store the TCPProxy pointer
		ingressOriginal.Listener.delegateTCPProxy = tcpProxyToDelegate
		recv.log.Debug("delegate TCPProxy", "tcpProxyToDelegate", *tcpProxyToDelegate)
		// since delegation is resolved break out of resolving "for" loop
		break
	}

	for ns, delegates := range failedDelegations {
		for _, delegate := range delegates {
			recv.getNS(ns).addFailedDelegation(
				recv.log, delegate,
				recv.getNS(ingressOriginal.Namespace).getIngressPtr(ingressOriginal),
			)
		}
	}
}

func (recv *CRDHandler) checkFQDN(ingress *Ingress) {
	if strings.Contains(ingress.Fqdn, "*") {
		if !strings.HasPrefix(ingress.Fqdn, "*") {
			ingress.SetInvalid("Wildcard misplaced in FQDN")
			return
		}
	}

	ingressDomains := make(map[string]struct{})
	for _, d := range ingress.VirtualHost.Domains {
		ingressDomains[d] = struct{}{}
	}

	recv.mapIngresses(func(ingress2 *Ingress) (stop bool) {
		if ingress == ingress2 {
			return
		}
		// can't compare pointers when checking failed delegation
		// during an update triggered by migration
		if ingress.Name == ingress2.Name &&
			ingress.Namespace == ingress2.Namespace &&
			ingress.TypeURL == ingress2.TypeURL {
			return
		}

		if ingress.Fqdn != "" &&
			ingress.Class == ingress2.Class &&
			ingress.Fqdn == ingress2.Fqdn {

			// handle migration
			if ingress.Analogous(ingress2) {
				recv.log.Debug("ignoring analogous ingress (fqdn)",
					"ns", ingress.Namespace, "name", ingress.Name,
					"existing", ingress2.TypeURL, "new", ingress.TypeURL,
					annotations.IC, ingress.Class,
				)
			} else {
				recv.log.Warn("FQDN collision. ns1/name1 is rejected",
					"ns1", ingress.Namespace, "name1", ingress.Name,
					"ns2", ingress2.Namespace, "name2", ingress2.Name,
					annotations.IC, ingress.Class,
				)
				ingress.SetInvalid(fmt.Sprintf("FQDN collision %s with %s in %s", ingress.Fqdn, ingress2.Name, ingress2.Namespace))
				stop = true
				return
			}
		}

		if ingress2.VirtualHost.Domains != nil &&
			ingress.Class == ingress2.Class {

			// handle migration
			if ingress.Analogous(ingress2) {
				recv.log.Debug("ignoring analogous ingress (domains)",
					"ns", ingress.Namespace, "name", ingress.Name,
					"existing", ingress2.TypeURL, "new", ingress.TypeURL,
					annotations.IC, ingress.Class,
				)
			} else {
				// check domains in other Ingresses
				for _, d := range ingress2.VirtualHost.Domains {
					if _, exists := ingressDomains[d]; exists {
						recv.log.Warn("Domain collision. ns1/name1 is rejected",
							"ns1", ingress.Namespace, "name1", ingress.Name,
							"ns2", ingress2.Namespace, "name2", ingress2.Name,
							annotations.IC, ingress.Class,
						)
						ingress.SetInvalid(fmt.Sprintf("Hosts collision '%s' with %s in %s", d, ingress2.Name, ingress2.Namespace))
						stop = true
						return
					}
					// check fqdn against these domains
					if ingress.Fqdn == d {
						recv.log.Warn("Fqdn/domain collision. ns1/name1 is rejected",
							"ns1", ingress.Namespace, "name1", ingress.Name,
							"ns2", ingress2.Namespace, "name2", ingress2.Name,
							annotations.IC, ingress.Class,
						)
						ingress.SetInvalid(fmt.Sprintf("Fqdn/hosts collision '%s' with %s in %s", ingress.Fqdn, ingress2.Name, ingress2.Namespace))
						stop = true
						return
					}
				}

				// check fqdn in other Ingresses
				if _, exists := ingressDomains[ingress2.Fqdn]; exists {
					recv.log.Warn("Domain/fqdn collision. ns1/name1 is rejected",
						"ns1", ingress.Namespace, "name1", ingress.Name,
						"ns2", ingress2.Namespace, "name2", ingress2.Name,
						annotations.IC, ingress.Class,
					)
					ingress.SetInvalid(fmt.Sprintf("Hosts/fqdn collision '%s' with %s in %s", ingress2.Fqdn, ingress2.Name, ingress2.Namespace))
					stop = true
					return
				}
			}
		}
		return
	})
}

func (recv *CRDHandler) mutateTLS(ingress *Ingress) {
	tls := ingress.Listener.TLS
	if tls == nil || tls.Passthrough {
		return
	}

	tls.MinProtocolVersion = minTLSVersion(recv.lc, ingress.Class, tls.MinProtocolVersion)

	if tls.MaxProtocolVersion == 0 {
		tls.MaxProtocolVersion = constants.DefaultMaxTLSVersion
	}

	if tls.SecretName == "" {
		if ic, exists := recv.lc.IngressClasses[ingress.Class]; exists && ic.DefaultCert != "" {
			tls.SecretName = ic.DefaultCert
			recv.log.Debug("using default cert",
				"ns", ingress.Namespace, "name", ingress.Name, "cert", ic.DefaultCert)
		} else {
			recv.log.Warn("no SecretName and no default cert",
				"ns", ingress.Namespace, "name", ingress.Name)

			ingress.SetInvalid("missing TLS secret name and there is no default cert")
			return
		}
	}

	parts := strings.Split(tls.SecretName, constants.SecretsDelimiter)
	switch len(parts) {
	case 1:
		// implicitly referencing a secret in the Ingress's own namespace
		//
		// rewrite the secret name to include the namespace since that's how
		// secrets are stored in recv.secrets
		tls.SecretName = ingress.Namespace + constants.SecretsDelimiter + parts[0]
	case 2:
		// explicit namespace
		if recv.delegationAllowed(parts[0], parts[1], ingress.Namespace) {
			recv.log.Debug("certificate delegation ALLOWED",
				"ns", ingress.Namespace, "name", ingress.Name, "secret_name", tls.SecretName)
		} else {
			recv.log.Warn("certificate delegation not allowed",
				"ns", ingress.Namespace, "name", ingress.Name, "secret_name", tls.SecretName)
			ingress.SetInvalid(fmt.Sprintf("certificate delegation of %s not allowed", tls.SecretName))
		}
	default:
		recv.log.Warn("invalid SecretName on Ingress",
			"ns", ingress.Namespace, "name", ingress.Name, "secret_name", tls.SecretName)

		ingress.SetInvalid("invalid TLS secret name")
	}
}

func (recv *CRDHandler) mutateIngress(ingress, ingressOld *Ingress) {
	if ingressOld != nil {
		recv.resolveRouteDelegations(ingressOld)
		recv.resolveTCPProxyDelegation(ingressOld)
		recv.mutateTLS(ingressOld)
		recv.checkAuth(ingressOld)

		// During an update the service references could change so we assume a
		// change and cleanup references here
		//
		// Do this after resolving delegations
		recv.deleteCluster2Ingress(ingressOld)
	}

	if ingress == nil {
		return
	}

	// All Ingresses start off as valid
	ingress.SetValid()

	// Until proven otherwise
	ingress.Validate()

	// If we have structural errors don't continue with additional processing that
	// may produce warnings when the Ingress is SetInvalid()
	//
	// If this is a Delegator it will resolve its Delegates once it becomes valid again
	//
	// If this is a Delegate its Delegators will resolveRouteDelegations via
	// checkFailedDelegations once it becomes valid again
	if ingress.Valid() {
		recv.checkFQDN(ingress)
		recv.mutateTLS(ingress)
	}

	var authIssue bool
	if ingress.Valid() {
		recv.checkAuth(ingress)
		if !ingress.Valid() {
			authIssue = true
		}
	}

	if !ingress.Valid() {
		if err := ingress.ValidationError; err != "" {
			recv.log.Warn("Invalid Ingress", "ns", ingress.Namespace, "name", ingress.Name, "err", err)
		} else if err := ingress.CRDError; err != "" {
			recv.log.Warn("Invalid Ingress", "ns", ingress.Namespace, "name", ingress.Name, "err", err)
		}
	}

	if authIssue {
		recv.updateStatus(ingress)
		return
	}

	// We maintain references even if the Ingress is invalid
	// (except in case of root auth issues)
	//
	// The alternative will only cause issues if this Ingress becomes valid again
	//
	// Do this after resolving delegations because it may add Cluster references
	// via delegated Routes and delegated TCPProxy
	recv.resolveRouteDelegations(ingress)
	recv.resolveTCPProxyDelegation(ingress)
	recv.addCluster2Ingress(ingress)

	recv.updateStatus(ingress)
}

func (recv *CRDHandler) updateStatus(ingress *Ingress) {
	switch recv.InCharge() {
	case types.Yes, types.Unknown: // don't miss status updates. writing status twice is tolerable
		recv.statusHandler.updateStatus(ingress)
	default:
		recv.log.Debug("ignoring status update", "reason", "not in charge")
	}
}

func (recv *CRDHandler) delegatorsFunc(possibleDelegate *Ingress) func(bool) {
	possibleDelegators := make(map[*Ingress]interface{})
	// Ensure that we capture any Ingresses that have delegates
	//
	// Service reference updates could cause these to otherwise be missed
	//
	// The map ensures multiple updates don't happen for the same Ingress
	possibleDelegate.mapClusters(func(xCluster Cluster, ns string) (stop bool) {
		iList := recv.getIngressList(possibleDelegate.Namespace, xCluster.Name)
		for _, ingress := range iList {
			// can't delegate across different Ingress types
			if ingress.TypeURL != possibleDelegate.TypeURL {
				continue
			}

			// can't compare pointers when used in updates
			if ingress.Namespace == possibleDelegate.Namespace &&
				ingress.Name == possibleDelegate.Name {

				continue
			}
			recv.log.Debug("delegatorsFunc possible Delegator",
				"ns", ingress.Namespace, "name", ingress.Name)
			possibleDelegators[ingress] = nil
		}
		return
	})

	return func(triggerXDS bool) {
		for ingress := range possibleDelegators {
			recv.mutateIngress(ingress, nil)
			if !triggerXDS {
				continue
			}

			if ingress.Valid() {
				recv.updateRDS(ingress, nil)
				recv.updateLDS(ingress, nil)
			} else {
				// cleanup of CDS or EDS resources is done in cleanXDS
				recv.removeFilterChainMatch(ingress)
				recv.removeVirtualHost(ingress)
			}
		}
	}
}

func (recv *CRDHandler) checkFailedDelegations(ingress *Ingress, triggerXDS bool) {
	nsCRDs := recv.getNS(ingress.Namespace)
	if iPtrList := nsCRDs.failedDelegations[ingress.Name]; iPtrList != nil {
		// make a copy because failedDelegations and
		// the original iPtrList are going to be modified
		// in resolveRouteDelegations and/or in resolveTCPProxyDelegation
		iPtrListCopy := make([]**Ingress, len(iPtrList))
		copy(iPtrListCopy, iPtrList)
		for _, iPtr := range iPtrListCopy {
			// ignore failed delegations that have the same name but a different type
			if (*iPtr).TypeURL != ingress.TypeURL {
				continue
			}
			recv.log.Debug("mutating Ingress for failed delegation")

			iPtrOld := (*iPtr).DeepCopy()

			// this is effectively an update of the delegator which now has
			// different config
			recv.mutateIngress(*iPtr, iPtrOld)
			if triggerXDS {
				recv.updateRDS(*iPtr, iPtrOld)
				recv.updateLDS(*iPtr, iPtrOld)
			}
		}
	}
}

// delegationAllowed figures out whether a secret (e.g. secretNS/secretName)
// can be delegated to the given namespace
func (recv *CRDHandler) delegationAllowed(secretNS, secretName, ns string) (answer bool) {
	// secrets in a given namespace are implicitely delegated to the entire namespace
	if secretNS == ns {
		answer = true
		return
	}
outer:
	for _, k := range recv.tlsDelegations {
		if k.Namespace_() != secretNS {
			continue
		}
		for _, d := range k.Delegations() {
			if d.SecretName() != secretName {
				continue
			}
			for _, t := range d.TargetNamespaces() {
				if t == "*" || t == ns {
					answer = true
					break outer
				}
			}
		}
	}
	return
}

// common between LDS and RDS
func (recv *CRDHandler) commonUpdateLogic(ingress, ingressOld *Ingress,
	f func(*Ingress)) (success bool) {
	if ingress == nil {
		recv.log.Warn("Ingress is nil")
		return
	}

	if ingress.Class == "" {
		// the ingress class was removed
		if ingressOld != nil {
			f(ingressOld)
		}
		return
	}

	if ingressOld != nil {
		if ingressOld.Fqdn != ingress.Fqdn {
			// the fqdn changed
			f(ingressOld)
		} else if ingress.Class != ingressOld.Class {
			// the ingress class changed
			f(ingressOld)
		}
	}

	success = true
	return
}

func (recv *CRDHandler) channelMonitor(ctx context.Context, exitChan chan<- uint8) {
	var (
		lastBacklog           int
		backlogStallCount     uint
		backlogStallThreshold uint
	)

	loopInterval := 10 * time.Second
	if resync := config.K8sResyncInterval(); resync > loopInterval {
		// don't let resyncs stack
		backlogStallThreshold = uint(resync / loopInterval)
	} else {
		backlogStallThreshold = 60 // 10 minutes
	}

	t := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(loopInterval)

			backlog := len(recv.events)
			if backlog > 0 {
				if backlog >= lastBacklog {
					backlogStallCount++
				} else {
					backlogStallCount = 0
				}
				recv.log.Info("informer events backlog", "len", backlog, "stalled", backlogStallCount)
			}
			lastBacklog = backlog

			if backlogStallCount > backlogStallThreshold {
				recv.log.Crit("informer backlog has been increasing. mitigating Envoy sync issue",
					"threshold", backlogStallThreshold)
				exitChan <- 1
			}
		}
	}
}

func (recv *CRDHandler) CleanupXDS() {
	for _, sotw := range recv.envoySubsets {
		activeCDS := set.New()

		for _, iface := range sotw.rds {
			iface.(xds.Wrapper).Read(func(msg proto.Message, meta interface{}) {
				rc := msg.(*route.RouteConfiguration)

				xds.MapVHosts(rc, func(vh *route.VirtualHost) {
					xds.MapClusterNames(vh, func(clusterName string) {
						activeCDS[clusterName] = nil
					})
				})
			})
		}

		for _, iface := range sotw.lds {
			iface.(xds.Wrapper).Read(func(msg proto.Message, meta interface{}) {
				l := msg.(*listener.Listener)

				xds.MapTCPProxyClusters(recv.log, l, func(clusterName string) {
					activeCDS[clusterName] = nil
				})

				xds.MapGRPCALSClusters(recv.log, l, func(clusterName string) {
					activeCDS[clusterName] = nil
				})
			})
		}

		// everything left behind in CDS SotW minus all that's actually
		// programmed in RDS/LDS SotW references to CDS entries
		leftoverCDS := set.Difference(sotw.cds, activeCDS)
		delete(leftoverCDS, constants.StatsCluster)
		delete(leftoverCDS, constants.ExtAuthzCluster)
		if RateLimitEnabled() {
			delete(leftoverCDS, RatelimitClusterName())
		}
		if recv.authzCluster != nil {
			delete(leftoverCDS, AuthzCluster().Name)
		}

		anyDeleted := false

		for name := range leftoverCDS {
			anyDeleted = true
			delete(sotw.cds, name)
			delete(sotw.eds, name)
			recv.log.Info("cleaned up CDS/EDS", "name", name)
		}

		if anyDeleted {
			recv.updateSotW(sotw.subset, xds.ClusterType, sotw.cds)
			recv.updateSotW(sotw.subset, xds.EndpointType, sotw.eds)
		}
	}
}

func (recv *CRDHandler) addIngress(ingress *Ingress) {
	log := recv.log

	nsCRDs := recv.getNS(ingress.Namespace)
	if !nsCRDs.addIngress(log, recv.lc, ingress) {
		return
	}
	recv.mutateIngress(ingress, nil)
	log.Debug("add Ingress",
		"cluster2ingress", recv.cluster2ingress,
		"name", ingress.Name, "type", ingress.TypeURL)

	if recv.migrateIngress(ingress, nil) {
		if ingress.Valid() {
			recv.checkFailedDelegations(ingress, !doTriggerXDS)
		}
		return
	}

	if ingress.Valid() {
		recv.updateCDS(ingress.Namespace, ingress.Name)
		recv.updateEDS(ingress.Namespace, ingress.Name)
		recv.updateLDS(ingress, nil)
		recv.updateRDS(ingress, nil)
		recv.updateSDS(ingress, nil)
		recv.checkFailedDelegations(ingress, doTriggerXDS)
	}
}

func (recv *CRDHandler) updateIngress(old, new *Ingress) {
	log := recv.log

	// we get updates for Ingresses with a ingress class other
	// than what we're configured to handle
	//
	// if we were previously tracking this Ingress then delete it
	//
	// otherwise there's nothing to do
	if !recv.getNS(new.Namespace).addIngress(log, recv.lc, new) {
		iPtr := recv.getNS(new.Namespace).getIngressPtr(new)
		if iPtr == nil {
			return
		} else {
			recv.OnDelete(new)
		}
	}

	// capture possible delegators so we can process them
	// after new is mutated
	df := recv.delegatorsFunc(old)

	recv.mutateIngress(new, old)

	if recv.migrateIngress(new, old) {
		df(!doTriggerXDS)
		if new.Valid() {
			recv.checkFailedDelegations(new, !doTriggerXDS)
		}
		return
	}

	df(doTriggerXDS)

	if new.Valid() {
		recv.updateCDS(new.Namespace, new.Name)
		recv.updateEDS(new.Namespace, new.Name)
		recv.updateLDS(new, old)
		recv.updateRDS(new, old)
		recv.updateSDS(new, old)
		recv.checkFailedDelegations(new, doTriggerXDS)
	} else {
		recv.removeFilterChainMatch(old)
		recv.removeVirtualHost(old)
	}
}

func (recv *CRDHandler) deleteIngress(ingress *Ingress) {
	// we get deletions for Ingresses with a ingress class other
	// than what we're configured to handle
	//
	// if we weren't previously tracking this Ingress then
	// there's nothing to do
	if iPtr := recv.getNS(ingress.Namespace).getIngressPtr(ingress); iPtr == nil {
		return
	}

	df := recv.delegatorsFunc(ingress)

	recv.mutateIngress(nil, ingress)

	recv.getNS(ingress.Namespace).deleteIngress(recv.log, ingress)
	recv.removeUnreferencedSecrets(ingress)
	recv.cleanupFailedDelegations(ingress)

	if recv.migrateIngress(nil, ingress) {
		df(!doTriggerXDS)
		return
	}

	recv.removeFilterChainMatch(ingress)
	recv.removeVirtualHost(ingress)

	df(doTriggerXDS)
}

func (recv *CRDHandler) addUpdateService(service *k8s.Service) {
	recv.getNS(service.Namespace).addService(recv.log, service)

	recv.updateCDS(service.Namespace, service.Name)

	// Service can arrive after Endpoints
	recv.updateEDS(service.Namespace, service.Name)

	// Service is needed to form the cluster name and weights
	// attached to the Route
	recv.updateRDS(service, nil)

	// In a Gateway, Service is needed to form the cluster name
	// and weights attached to a TCP proxy
	//
	// In a Sidecar, Service's ServicePort is used for the
	// Listener's port
	recv.updateLDS(service, nil)
}

// CDS and EDS SotWs are handled in CleanupXDS
func (recv *CRDHandler) deleteService(service *k8s.Service) {
	recv.getNS(service.Namespace).deleteService(recv.log, service)

	// Service is needed to form the cluster name and weights
	// attached to the Route
	recv.updateRDS(service, nil)

	// In a Gateway, Service is needed to form the cluster name
	// and weights attached to a TCP proxy
	//
	// In a Sidecar, Service's ServicePort is used for the
	// Listener's port
	recv.updateLDS(service, nil)
}

func (recv *CRDHandler) addNode(node *k8s.Node) {
	zone := node.Labels[constants.TopologyZoneLabel]
	if zone == "" {
		recv.log.Info("missing/empty node label "+constants.TopologyZoneLabel, "node", node.Name)
		return
	}

	matches := ipv4CIDRRE.FindStringSubmatch(node.Spec.PodCIDR)
	if len(matches) != 6 {
		recv.log.Warn("bad node podCIDR", "podCIDR", node.Spec.PodCIDR, "node", node.Name)
		return
	}

	// ["172.18.18.0/24" "172" "18" "18" "0" "24"] = FindStringSubmatch("172.18.18.0/24")
	o1, err1 := strconv.Atoi(matches[1]) // first capture group
	o2, err2 := strconv.Atoi(matches[2])
	o3, err3 := strconv.Atoi(matches[3])
	o4, err4 := strconv.Atoi(matches[4])
	mask, err5 := strconv.Atoi(matches[5])

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		recv.log.Warn("strconv.Atoi",
			"o1", o1, "err1", err1,
			"o2", o2, "err2", err2,
			"o3", o3, "err3", err3,
			"o4", o4, "err4", err4,
			"mask", mask, "err5", err5,
		)
		return
	}

	recv.log.Info("added Node", "name", node.Name, "podCIDR", matches[0], "zone", zone)

	ipv4 := uint32(o1)<<24 | uint32(o2)<<16 | uint32(o3)<<8 | uint32(o4)

	var i uint32 = 1                  // exclude the network itself
	for ; i < (1<<(32-mask))-1; i++ { // exclude the broadcast address
		recv.ip2zone[ipv4|i] = zone
	}
}

func (recv *CRDHandler) addSecret(kSecret *k8s.Secret) (success bool) {
	if kSecret.Type != k8s.SecretTypeTLS {
		return
	}

	recv.secrets[SecretsKey(kSecret)] = kSecret
	recv.log.Info("add/update Secret", "ns", kSecret.Namespace, "name", kSecret.Name)
	success = true
	return
}

func (recv *CRDHandler) deleteSecret(kSecret *k8s.Secret) (success bool) {
	if _, exists := recv.secrets[SecretsKey(kSecret)]; exists {
		recv.log.Info("delete Secret", "ns", kSecret.Namespace, "name", kSecret.Name)
		delete(recv.secrets, SecretsKey(kSecret))
		success = true
	}
	return
}

func (recv *CRDHandler) addCertDelegation(certDelegation TLSCertificateDelegation) (success bool) {
	delegationName := tlsDelegationKey(certDelegation)
	// A little bit of validation
	if len(certDelegation.Delegations()) == 0 {
		recv.log.Warn("TLSCertificateDelegation has no 'delegations'", "name", delegationName)
		return
	}

	for _, d := range certDelegation.Delegations() {
		if len(d.SecretName()) == 0 || len(d.TargetNamespaces()) == 0 {
			recv.log.Warn("TLSCertificateDelegation: secretName and targetNamespaces are required", "name", delegationName)
			return
		}
	}
	recv.log.Info("add/update TLSCertificateDelegation", "name", delegationName)
	recv.tlsDelegations[delegationName] = certDelegation

	success = true
	return
}

func (recv *CRDHandler) deleteCertDelegation(certDelegation TLSCertificateDelegation) (success bool) {
	delegationName := tlsDelegationKey(certDelegation)
	if _, exists := recv.tlsDelegations[delegationName]; exists {
		recv.log.Info("delete TLSCertificateDelegation", "name", delegationName)
		delete(recv.tlsDelegations, delegationName)
		success = true
	}
	return
}

func (recv *CRDHandler) loop(ctx context.Context, exitChan chan<- uint8, syncChan chan<- struct{}) {
	log := recv.log
	log.Info("starting ResourceEventHandler")

	var stopped bool
	defer func() {
		if !stopped {
			log.Crit("broke out of CRDHandler loop")
			exitChan <- 1
		}
	}()

	// we assume k8s.Start informers begin adding resources before the first tick
	syncTimer := time.NewTimer(0)
	cleanupTimer := time.NewTimer(0)

	enterLoopTime := time.Now()
	lastAdd := enterLoopTime
	addCount := 6 // > 5
	addCountTotal := 0

	for {
		select {
		case <-ctx.Done():
			stopped = true
			log.Info("ResourceEventHandler stopped")
			return

		case <-cleanupTimer.C:
			cleanupTimer.Reset(time.Minute)
			if !config.Testing() {
				recv.CleanupXDS()
			}

		case <-syncTimer.C:

			addCountTotal += addCount

			if addCount > 5 {
				log.Info("initial sync", "addCount", addCount)
				addCount = 0
				// resources are still coming in at a rapid rate (> 1/s) so we
				// assume initial informer sync is still in progress
				syncTimer.Reset(5 * time.Second)
			} else {
				if lastAdd == enterLoopTime {
					log.Warn("no addEvents. assuming K8s connectivity issue and preventing xDS communication")
					syncTimer.Reset(time.Second)
				} else if config.MTLS() && !recv.canMTLS() {
					log.Warn("waiting for mTLS capability")
					syncTimer.Reset(time.Second)
				} else {
					log.Info("closing syncChan", "addCountTotal", addCountTotal)
					// we think we've synced all resources from the informers
					close(syncChan)
					// now, we can update all ingress statuses
					statusUpdateHandler.startStatusHandler(ctx)
					recv.mapIngresses(func(ingress *Ingress) (stop bool) {
						recv.updateStatus(ingress)
						return
					})
				}
			}

		case iface := <-recv.events:
			xlateEventsBacklog.Dec()

			switch event := iface.(type) {

			case addEvent:
				lastAdd = time.Now()
				addCount++

				switch crd := event.iface.(type) {

				// only handle addEvent because the callback is a pointer which
				// can be updated
				case xds.DiscoveryCallbacks:
					switch crd.Type {
					case xds.ClusterType:
						for name, sotw := range recv.envoySubsets {
							sotw.cds[string(name)] = crd
						}
					case xds.EndpointType:
						for name, sotw := range recv.envoySubsets {
							sotw.eds[string(name)] = crd
						}
					case xds.ListenerType:
						for name, sotw := range recv.envoySubsets {
							sotw.lds[string(name)] = crd
						}
					case xds.RouteType:
						for name, sotw := range recv.envoySubsets {
							sotw.rds[string(name)] = crd
						}
					case xds.SecretType:
						for name, sotw := range recv.envoySubsets {
							sotw.sds[string(name)] = crd
						}
					default:
						log.Error("missing/invalid Type on DiscoveryCallbacks")
					}

				case *Ingress:
					recv.addIngress(crd)

				case *k8s.Service:
					recv.addUpdateService(crd)

				case *k8s.Endpoints:
					recv.getNS(crd.Namespace).addEndpoints(log, crd)
					recv.updateCDS(crd.Namespace, crd.Name) // dynamic circuit breaking
					recv.updateEDS(crd.Namespace, crd.Name)

				case *k8s.Node:
					recv.addNode(crd)

				case *k8s.Secret:
					if recv.addSecret(crd) {
						recv.updateSDS(crd, nil)
						recv.tryMTLS(crd)
					}

				case TLSCertificateDelegation:
					if recv.addCertDelegation(crd) {
						// Any invalid Ingress referencing these delegated secrets can now become valid
						tlsDelegations := tlsDelegationMap(crd)
						recv.mapIngresses(func(ingress *Ingress) (stop bool) {
							if ingress.Valid() {
								return
							}
							lstnr := ingress.Listener
							if lstnr.TLS != nil && lstnr.TLS.SecretName != "" {
								if delegations, ok := tlsDelegations[lstnr.TLS.SecretName]; ok {
									// Check if the namespace for this invalid ingress is now allowed
									_, ok1 := delegations["*"]
									_, ok2 := delegations[ingress.Namespace]
									if ok1 || ok2 {
										recv.mutateIngress(ingress, nil)
										if ingress.Valid() {
											if !recv.isHighestPriorityIngress(ingress) {
												recv.checkFailedDelegations(ingress, !doTriggerXDS)
												return
											}
											recv.updateCDS(ingress.Namespace, ingress.Name)
											recv.updateEDS(ingress.Namespace, ingress.Name)
											recv.updateLDS(ingress, nil)
											recv.updateRDS(ingress, nil)
											recv.updateSDS(ingress, nil)
											recv.checkFailedDelegations(ingress, doTriggerXDS)
										}
									}
								}
							}
							return
						})
					}

				case *crds.Sidecar:
					recv.getNS(crd.Namespace).addSidecar(recv.log, crd)
					recv.addSotW(subsetsKey(crd), SidecarRole, crd)

					if ingress := recv.sidecarIngress(crd); ingress != nil {
						// the Endpoint is static and there are no Secrets
						recv.updateCDS(ingress.Namespace, ingress.Name)
						recv.updateLDS(ingress, nil)
						recv.updateRDS(ingress, nil)
					}

				default:
					log.Error("unhandled crd", "type", fmt.Sprintf("%T", crd))

				} // switch

			case updateEvent:
				switch crd := event.new.(type) {
				case *Ingress:
					crdOld := event.old.(*Ingress)
					recv.updateIngress(crdOld, crd)

				case *k8s.Service:
					recv.addUpdateService(crd)

				case *k8s.Endpoints:
					recv.getNS(crd.Namespace).addEndpoints(log, crd)
					recv.updateCDS(crd.Namespace, crd.Name) // dynamic circuit breaking
					recv.updateEDS(crd.Namespace, crd.Name)

				case *k8s.Node:
					recv.addNode(crd)

				case *k8s.Secret:
					if recv.addSecret(crd) {
						crdOld := event.old.(*k8s.Secret)
						recv.updateSDS(crd, crdOld)
					}

				case TLSCertificateDelegation:
					if recv.addCertDelegation(crd) {
						// Such update can both invalidate existing Ingresses or make them valid
						// So we have to look at all of them

						tlsDelegations := tlsDelegationMap(crd)
						// First, the invalid Ingresses
						recv.mapIngresses(func(ingress *Ingress) (stop bool) {
							if ingress.Valid() {
								return
							}
							lstnr := ingress.Listener
							if lstnr.TLS != nil && lstnr.TLS.SecretName != "" {
								if delegations, ok := tlsDelegations[lstnr.TLS.SecretName]; ok {
									// Check if the namespace for this invalid ingress is now allowed
									// TODO(lrouquet): this might the same as the one for addEvent
									_, ok1 := delegations["*"]
									_, ok2 := delegations[ingress.Namespace]
									if ok1 || ok2 {
										recv.mutateIngress(ingress, nil)
										if ingress.Valid() {
											if !recv.isHighestPriorityIngress(ingress) {
												recv.checkFailedDelegations(ingress, !doTriggerXDS)
												return
											}
											recv.updateCDS(ingress.Namespace, ingress.Name)
											recv.updateEDS(ingress.Namespace, ingress.Name)
											recv.updateLDS(ingress, nil) // e.g. remove it!
											recv.updateRDS(ingress, nil)
											recv.updateSDS(ingress, nil)
											recv.checkFailedDelegations(ingress, doTriggerXDS)
										}
									}
								}
							}
							return
						})

						// Now, the valid ones
						recv.mapIngresses(func(ingress *Ingress) (stop bool) {
							if !ingress.Valid() {
								return
							}
							lstnr := ingress.Listener
							if lstnr.TLS != nil && lstnr.TLS.SecretName != "" {
								if delegations, ok := tlsDelegations[lstnr.TLS.SecretName]; ok {
									// Check if the namespace of this valid ingress is no longer allowed
									_, ok1 := delegations["*"]
									_, ok2 := delegations[ingress.Namespace]
									if !(ok1 || ok2) { // both are false
										// from Ingress.update
										ingressOld := ingress.DeepCopy()
										df := recv.delegatorsFunc(ingressOld)
										recv.mutateIngress(ingress, ingressOld)
										if !recv.isHighestPriorityIngress(ingress) {
											df(!doTriggerXDS)
											return
										}
										df(doTriggerXDS)
										if !ingress.Valid() {
											recv.removeFilterChainMatch(ingressOld)
											recv.removeVirtualHost(ingressOld)
										}
									}
								}
							}
							return
						})
					}

				case *crds.Sidecar:
					recv.getNS(crd.Namespace).addSidecar(recv.log, crd)
					recv.addSotW(subsetsKey(crd), SidecarRole, crd)

					if ingress := recv.sidecarIngress(crd); ingress != nil {
						// the Endpoint is static and there are no Secrets
						recv.updateCDS(ingress.Namespace, ingress.Name)
						recv.updateLDS(ingress, nil)
						recv.updateRDS(ingress, nil)
					}

				default:
					log.Error("unhandled crd", "type", fmt.Sprintf("%T", crd))

				} // switch

			case deleteEvent:
				switch crd := event.iface.(type) {
				case *Ingress:
					recv.deleteIngress(crd)

				case *k8s.Service:
					recv.deleteService(crd)

				case *k8s.Endpoints: // CDS and EDS SotWs are handled in CleanupXDS
					recv.getNS(crd.Namespace).deleteEndpoints(log, crd)

				case *k8s.Node:
					// TODO(bcook) recv.deleteNode?

				case *k8s.Secret:
					// don't delete a Secret just because we're told to
					//
					// check for references in XDS
					if recv.removeUnreferencedSecretByName(SecretsKey(crd)) {
						recv.deleteSecret(crd)
					} else {
						// This can lead to a state where everything is fine for
						// the Envoys with the Secret but new Envoys will have a
						// different state, and a restart of KAPCOM could lead to
						// the same. Envoy is fine warming a Secret while waiting
						// for it to be sent. It's not fine losing an active
						// secret that's still referenced
						//
						// The assumption here is that the Ingress is about
						// to be deleted as well (e.g. kubectl delete -f)
						//
						// We have to treat it this way because removing a
						// referenced Secret from SDS causes instability
						//
						// TODO(bcook) should we be removing the references?
						// lrouquet: maybe: see https://git.corp.adobe.com/adobe-platform/kapcom/issues/182
						// TODO(lrouquet): need to think about this some more
						log.Warn("a Secret was deleted from K8s but is still referenced in XDS",
							"ns", crd.Namespace, "name", crd.Name)
					}

				case TLSCertificateDelegation:
					if recv.deleteCertDelegation(crd) {
						// Any valid Ingress referencing these secrets can now become invalid

						tlsDelegations := tlsDelegationMap(crd)
						recv.mapIngresses(func(ingress *Ingress) (stop bool) {
							if !ingress.Valid() {
								return
							}
							lstnr := ingress.Listener
							if lstnr.TLS != nil && lstnr.TLS.SecretName != "" {
								if delegations, ok := tlsDelegations[lstnr.TLS.SecretName]; ok {
									// Check if the namespace of this a valid ingress was allowed
									_, ok1 := delegations["*"]
									_, ok2 := delegations[ingress.Namespace]
									if ok1 || ok2 { // one of them "was" true
										// from Ingress.update
										ingressOld := ingress.DeepCopy()
										df := recv.delegatorsFunc(ingressOld)
										recv.mutateIngress(ingress, ingressOld)
										if !recv.isHighestPriorityIngress(ingress) {
											df(!doTriggerXDS)
											return
										}
										df(doTriggerXDS)
										if !ingress.Valid() {
											recv.removeFilterChainMatch(ingressOld)
											recv.removeVirtualHost(ingressOld)
										}
									}
								}
							}
							return
						})
					}

				case *crds.Sidecar:
					recv.getNS(crd.Namespace).deleteSidecar(recv.log, crd)
					recv.deleteSotW(subsetsKey(crd))

					recv.updateCDS(crd.Namespace, crd.Spec.Ingress.Name)

				case cache.DeletedFinalStateUnknown:
					log.Info("handling deleted/state unknown", "key", crd.Key)
					recv.OnDelete(crd.Obj)

				default:
					log.Error("unhandled crd", "type", fmt.Sprintf("%T", crd))

				} // switch

			case httpEvent:

				namespaces := make(map[string]CRDLists)
				for name, crds := range recv.namespaces {

					lists := CRDLists{
						Ingresses: []string{},
						Services:  []string{},
						Endpoints: []string{},
					}

					for _, iMap := range crds.ingressTypes {
						for v := range iMap {
							lists.Ingresses = append(lists.Ingresses, v)
						}
					}
					for v := range crds.services {
						lists.Services = append(lists.Services, v)
					}
					for v := range crds.endpoints {
						lists.Endpoints = append(lists.Endpoints, v)
					}

					namespaces[name] = lists
				}

				res := SotWResponse{
					Namespaces: namespaces,
					CDSSotW:    []string{},
					EDSSotW:    []string{},
					LDSSotW:    []string{},
					RDSSotW:    []string{},
					SDSSotW:    []string{},
				}

				sotw := recv.envoySubsets[xds.DefaultEnvoySubset]
				for v := range sotw.cds {
					res.CDSSotW = append(res.CDSSotW, v)
				}
				for v := range sotw.eds {
					res.EDSSotW = append(res.EDSSotW, v)
				}
				for v := range sotw.lds {
					res.LDSSotW = append(res.LDSSotW, v)
				}
				for v := range sotw.rds {
					res.RDSSotW = append(res.RDSSotW, v)
				}
				for v := range sotw.sds {
					res.SDSSotW = append(res.SDSSotW, v)
				}

				event.responseChan <- res

			default:
				log.Error("CRDHandler received unknown event",
					"TypeOf", reflect.TypeOf(iface).String())
			}
		}
	}
}
