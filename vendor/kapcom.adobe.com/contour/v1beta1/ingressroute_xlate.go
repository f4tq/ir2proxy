package v1beta1

import (
	"strconv"
	"strings"
	"time"

	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/constants/annotations"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xlate"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// This can not change with the introduction of the EnvoySidecar CRD
const IngressTypeURL = "contour.heptio.com/v1beta1/IngressRoute"

type IRHandler struct {
	handler cache.ResourceEventHandler
	xlate.IngressStatus
}

func IngressRouteHandler(handler cache.ResourceEventHandler) cache.ResourceEventHandler {
	return &IRHandler{
		handler: handler,
	}
}

func (recv *IRHandler) OnAdd(iface interface{}) {
	if crd, ok := iface.(*IngressRoute); ok {
		iface = recv.CRDToIngress(crd)
	}
	recv.handler.OnAdd(iface)
}

func (recv *IRHandler) OnUpdate(old, new interface{}) {
	if oldCRD, ok := old.(*IngressRoute); ok {
		old = recv.CRDToIngress(oldCRD)
		new = recv.CRDToIngress(new.(*IngressRoute))
	}
	recv.handler.OnUpdate(old, new)
}

func (recv *IRHandler) OnDelete(iface interface{}) {
	if crd, ok := iface.(*IngressRoute); ok {
		iface = recv.CRDToIngress(crd)
	}
	recv.handler.OnDelete(iface)
}

func serviceToCluster(service *Service) xlate.Cluster {
	c := xlate.Cluster{}
	c.Name = service.Name
	c.Port = int32(service.Port)
	c.Weight = service.Weight

	switch service.Strategy {
	case "WeightedLeastRequest":
		c.LbPolicy = cluster.Cluster_LEAST_REQUEST
	case "Random":
		c.LbPolicy = cluster.Cluster_RANDOM
	case "RingHash":
		c.LbPolicy = cluster.Cluster_RING_HASH
	case "Maglev":
		c.LbPolicy = cluster.Cluster_MAGLEV
	default: // includes explicit RoundRobin
		c.LbPolicy = cluster.Cluster_ROUND_ROBIN
	}

	if service.IdleTimeout != nil {
		c.IdleTimeout = service.IdleTimeout.Duration
	}

	if service.ConnectTimeout != nil {
		c.ConnectTimeout = service.ConnectTimeout.Duration
	}

	if service.PerPodMaxConnections != 0 ||
		service.PerPodMaxPendingRequests != 0 ||
		service.PerPodMaxRequests != 0 {

		c.EndpointCircuitBreaker = &xlate.EndpointCircuitBreaker{
			MaxConnections:     service.PerPodMaxConnections,
			MaxPendingRequests: service.PerPodMaxPendingRequests,
			MaxRequests:        service.PerPodMaxRequests,
		}
	}

	if hc := service.HealthCheck; hc != nil {
		c.HealthCheck = &xlate.HealthCheck{
			Path:               hc.Path,
			Host:               hc.Host,
			Timeout:            time.Duration(hc.TimeoutSeconds) * time.Second,
			Interval:           time.Duration(hc.IntervalSeconds) * time.Second,
			UnhealthyThreshold: hc.UnhealthyThresholdCount,
			HealthyThreshold:   hc.HealthyThresholdCount,
		}
	}

	return c
}

func (recv *IRHandler) CRDToIngress(crd *IngressRoute) *xlate.Ingress {
	ingress := &xlate.Ingress{
		Name:      crd.Name,
		Namespace: crd.Namespace,
		TypeURL:   IngressTypeURL,
		Priority:  1,
	}

	if crd.Annotations == nil {
		ingress.CRDError = "Missing annotations"
	} else {
		ingress.Class = crd.Annotations[annotations.IC]
		if ingress.Class == "" {
			ingress.CRDError = "Missing or empty " + annotations.IC + " annotation"
		}
		if hostsAnnot := crd.Annotations[annotations.Hosts]; hostsAnnot != "" {
			// input validation: no empty values, no duplicates, no '*', no collision with fqdn
			// TODO: move this to xlate eventually; need to decide on a messaging strategy, which
			// may need to be relevant to the CRD...
			inHosts := strings.Split(hostsAnnot, ",")
			hostMap := make(map[string]bool)
			for _, h := range inHosts {
				if strings.Trim(h, " ") == "" {
					ingress.CRDError = "Empty value in " + annotations.Hosts + " annotation"
					break
				}
				// allow '*' with TLS (EON-30470)
				// currently, OPA restricts to a single one per ingress class
				// removing this restriction requires creating a dedicate Route in the HCM
				// which may be done in the future
				if h == "*" {
					if crd.Spec.VirtualHost == nil || crd.Spec.VirtualHost.TLS == nil {
						ingress.CRDError = "'*' " + annotations.Hosts + " annotation not allowed without TLS"
						break
					}
				} else if strings.Contains(h, "*") {
					ingress.CRDError = "Illegal charaters in " + annotations.Hosts + " annotation"
					break
				}
				if _, seen := hostMap[h]; seen {
					ingress.CRDError = "Duplicate value in " + annotations.Hosts + " annotation"
					break
				}
				if crd.Spec.VirtualHost != nil && crd.Spec.VirtualHost.Fqdn == h {
					ingress.CRDError = "Fqdn collision with " + annotations.Hosts + " annotation"
					break
				}
				hostMap[h] = true
			}
			ingress.VirtualHost.Domains = inHosts
		}
		if priorityAnnot := crd.Annotations[annotations.Priority]; priorityAnnot != "" {
			priority, err := strconv.ParseInt(priorityAnnot, 10, 0)
			if err == nil {
				ingress.Priority = int(priority)
			}
		}
	}

	if crd.Spec.VirtualHost != nil {
		ingress.Fqdn = crd.Spec.VirtualHost.Fqdn

		if crd.Spec.VirtualHost.TLS != nil {
			ingress.Listener.TLS = new(xlate.TLS)
			if ok, version := xlate.TLSProtocolVersion(crd.Spec.VirtualHost.TLS.MinimumProtocolVersion); ok {
				ingress.Listener.TLS.MinProtocolVersion = version
			}
			if ok, version := xlate.TLSProtocolVersion(crd.Spec.VirtualHost.TLS.MaximumProtocolVersion); ok {
				ingress.Listener.TLS.MaxProtocolVersion = version
			}
			ingress.Listener.TLS.SecretName = crd.Spec.VirtualHost.TLS.SecretName
			ingress.Listener.TLS.Passthrough = crd.Spec.VirtualHost.TLS.Passthrough

			for _, cs := range crd.Spec.VirtualHost.TLS.CipherSuites {
				if strings.Count(cs, "|") > 0 {
					ingress.Listener.TLS.CipherSuites = append(ingress.Listener.TLS.CipherSuites, "["+cs+"]")
				} else {
					ingress.Listener.TLS.CipherSuites = append(ingress.Listener.TLS.CipherSuites, cs)
				}
			}
		}
	}

	if crd.Spec.TCPProxy != nil {
		if len(crd.Spec.TCPProxy.Services) == 0 {
			ingress.CRDError = "TCPProxy has no Services"
		} else {
			ingress.Listener.TCPProxy = &xlate.TCPProxy{
				Clusters: make([]xlate.Cluster, len(crd.Spec.TCPProxy.Services)),
			}
			for i, service := range crd.Spec.TCPProxy.Services {
				ingress.Listener.TCPProxy.Clusters[i] = serviceToCluster(service)
			}
		}
	}

	routesLen := len(crd.Spec.Routes)
	if routesLen == 0 {
		if crd.Spec.TCPProxy == nil {
			ingress.CRDError = "Missing routes and tcpproxy"
		}
	} else {
		ingress.VirtualHost.Routes = make([]*xlate.Route, 0, routesLen)
	}

	routeMatchList := make(map[string][]xlate.HeaderMatcher)
	for _, route := range crd.Spec.Routes {
		if route.Match == "" {
			ingress.CRDError = "Route has no Match"
		}

		if len(route.Services) == 0 && route.Delegate == nil {
			ingress.CRDError = "Route has no Services or Delegate"
		}

		if hm, exists := routeMatchList[route.Match]; exists && len(route.HeaderMatch) == 0 && len(hm) == 0 {
			ingress.CRDError = "Duplicate Route Match " + route.Match
		} else {
			routeMatchList[route.Match] = route.HeaderMatch
		}

		if err := route.RequestHeadersPolicy.err(true); err != nil {
			ingress.CRDError = err.Error()
		}

		if err := route.ResponseHeadersPolicy.err(false); err != nil {
			ingress.CRDError = err.Error()
		}

		if len(route.HeaderMatch) > 0 {
			// validate
			// - contradictory operators
			// - duplicate "exact"
			// - "present == false" and any other operator
			type headerMatchMap map[xlate.HeaderMatcher]bool
			isPresentFalse := func(myMap headerMatchMap, header string) bool {
				for k := range myMap {
					if k.Name == header && k.Present != nil && *k.Present == false {
						return true
					}
				}
				return false
			}
			hmMap := make(headerMatchMap)

			for _, hm := range route.HeaderMatch {
				opCont := 0
				if hm.Name == "" {
					ingress.CRDError = "HeaderMatch Name can't be blank"
					break
				}

				if hm.Present != nil {
					// hm.Present is a pointer, so we can't direct compare
					foundIt := false
					for k := range hmMap {
						if k.Name == hm.Name && k.Present != nil && *k.Present == !*hm.Present {
							ingress.CRDError = "Contradictory `present` HeaderMatch"
							foundIt = true
							break
						}
						if k.Name == hm.Name && *hm.Present == false {
							ingress.CRDError = "Conflicting `present: false` and another operator in HeaderMatch"
							foundIt = true
							break
						}
					}
					if foundIt {
						break
					}
					opCont++
				}

				if hm.Contains != "" {
					if hmMap[xlate.HeaderMatcher{Name: hm.Name, NotContains: hm.Contains}] {
						ingress.CRDError = "Contradictory `contains` and `notcontains` HeaderMatch"
						break
					}
					if isPresentFalse(hmMap, hm.Name) {
						ingress.CRDError = "Conflicting `present: false` and `contains` operator in HeaderMatch"
						break
					}
					opCont++
				}

				if hm.NotContains != "" {
					if hmMap[xlate.HeaderMatcher{Name: hm.Name, Contains: hm.NotContains}] {
						ingress.CRDError = "Contradictory `contains` and `notcontains` HeaderMatch"
						break
					}
					if isPresentFalse(hmMap, hm.Name) {
						ingress.CRDError = "Conflicting `present: false` and `notcontains` operator in HeaderMatch"
						break
					}
					opCont++
				}

				if hm.Exact != "" {
					if hmMap[xlate.HeaderMatcher{Name: hm.Name, NotExact: hm.Exact}] {
						ingress.CRDError = "Contradictory `exact` and `notexact` HeaderMatch"
						break
					}
					if isPresentFalse(hmMap, hm.Name) {
						ingress.CRDError = "Conflicting `present: false` and `exact` operator in HeaderMatch"
						break
					}
					// duplicate "exact", presumably with different header values are not allowed
					foundIt := false
					for k := range hmMap {
						if k.Name == hm.Name && k.Exact != "" {
							ingress.CRDError = "Duplicate `exact` HeaderMatch"
							break
						}
					}
					if foundIt {
						break
					}
					opCont++
				}

				if hm.NotExact != "" {
					if hmMap[xlate.HeaderMatcher{Name: hm.Name, Exact: hm.NotExact}] {
						ingress.CRDError = "Contradictory `exact` and `notexact` HeaderMatch"
						break
					}
					if isPresentFalse(hmMap, hm.Name) {
						ingress.CRDError = "Conflicting `present: false` and `notexact` operator in HeaderMatch"
						break
					}
					opCont++
				}

				if opCont > 1 {
					ingress.CRDError = "Only one HeaderMatch operator can be specified"
					break
				}

				k := hm.DeepCopy()
				hmMap[*k] = true
			}
		}

		xRoute := new(xlate.Route)

		xRoute.Match = route.Match
		xRoute.PrefixRewrite = route.PrefixRewrite
		xRoute.SPDYUpgrade = route.EnableSPDY
		xRoute.WebsocketUpgrade = route.EnableWebsockets
		xRoute.HTTPSRedirect = !route.PermitInsecure
		xRoute.PerFilterConfig = route.PerFilterConfig
		xRoute.HeaderMatchers = route.HeaderMatch

		if route.Delegate != nil {
			xRoute.Delegate = &xlate.Delegate{
				Name:      route.Delegate.Name,
				Namespace: route.Delegate.Namespace,
			}
		}

		if route.RetryPolicy != nil {
			xRoute.RetryPolicy = &xlate.RetryPolicy{
				NumRetries:    route.RetryPolicy.NumRetries,
				PerTryTimeout: route.RetryPolicy.PerTryTimeout,
			}
		}

		if route.Timeout != nil {
			if route.Timeout.Duration == 0 {
				xRoute.Timeout = -1
			} else {
				xRoute.Timeout = route.Timeout.Duration
			}
		} else if route.TimeoutPolicy != nil {
			// Contour allows to specify an infinite timeout here
			// https://github.com/projectcontour/contour/blob/v1.8.1/internal/timeout/timeout.go#L57-L63
			// https://www.envoyproxy.io/docs/envoy/v1.15.0/api-v3/config/route/v3/route_components.proto#envoy-v3-api-field-config-route-v3-routeaction-timeout
			if route.TimeoutPolicy.Request == "infinity" {
				xRoute.Timeout = -1
			} else if route.TimeoutPolicy.Request != "" {
				d, _ := time.ParseDuration(route.TimeoutPolicy.Request)
				if d > 0 {
					xRoute.Timeout = d
				} else {
					ingress.CRDError = "invalid Route timeout"
				}
			}
		}

		if route.IdleTimeout != nil {
			xRoute.IdleTimeout = route.IdleTimeout.Duration
		}

		if len(route.HashPolicy) > 0 {
			xRoute.HashPolicies = make([]xlate.HashPolicy, len(route.HashPolicy))
			for i, hp := range route.HashPolicy {
				if hp.Header != nil {
					xRoute.HashPolicies[i].Header = &xlate.HashPolicyHeader{
						Name: hp.Header.HeaderName,
					}
				} else if hp.Cookie != nil {
					xRoute.HashPolicies[i].Cookie = &xlate.HashPolicyCookie{
						Name: hp.Cookie.Name,
						Path: hp.Cookie.Path,
					}
					if hp.Cookie.Ttl != nil {
						xRoute.HashPolicies[i].Cookie.Ttl = &hp.Cookie.Ttl.Duration
					}
				} else if hp.ConnectionProperties != nil {
					xRoute.HashPolicies[i].ConnectionProperties = &xlate.HashPolicyConnectionProperties{
						SourceIp: hp.ConnectionProperties.SourceIp,
					}
				}

				xRoute.HashPolicies[i].Terminal = hp.Terminal
			}
		}

		if route.RequestHeadersPolicy != nil {
			xRoute.RequestHeadersToAdd = make([]xlate.KVP, 0, len(route.RequestHeadersPolicy.Set))
			for _, hv := range route.RequestHeadersPolicy.Set {
				xRoute.RequestHeadersToAdd = append(xRoute.RequestHeadersToAdd, xlate.KVP{
					Key:   hv.Name,
					Value: util.EncodedHeaderValue(hv.Value),
				})
			}
			xRoute.RequestHeadersToRemove = route.RequestHeadersPolicy.Remove
		}

		if route.ResponseHeadersPolicy != nil {
			xRoute.ResponseHeadersToAdd = make([]xlate.KVP, len(route.ResponseHeadersPolicy.Set))
			for i, hv := range route.ResponseHeadersPolicy.Set {
				xRoute.ResponseHeadersToAdd[i].Key = hv.Name
				xRoute.ResponseHeadersToAdd[i].Value = util.EncodedHeaderValue(hv.Value)
			}
			xRoute.ResponseHeadersToRemove = route.ResponseHeadersPolicy.Remove
		}

		xRoute.Clusters = make([]xlate.Cluster, len(route.Services))
		for i, service := range route.Services {
			xRoute.Clusters[i] = serviceToCluster(service)
		}

		ingress.VirtualHost.Routes = append(ingress.VirtualHost.Routes, xRoute)
	}

	ingress.ResourceVersion = crd.ResourceVersion
	ingress.LastCRDStatus = crd.Status.Description

	return ingress
}

func IngressRouteStatusInterface() xlate.IngressStatus {
	return &IRHandler{}
}

func (recv *IRHandler) Type() string {
	return IngressTypeURL
}

func (recv *IRHandler) StatusChanged(ingress *xlate.Ingress) (bool, string) {
	newStatus := recv.computeStatus(ingress)
	return ingress.LastCRDStatus != newStatus.Description, newStatus.Description
}

func (recv *IRHandler) PrepareForStatusUpdate(ingress *xlate.Ingress) interface{} {
	ir := &IngressRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ingress.Namespace,
			Name:            ingress.Name,
			ResourceVersion: ingress.ResourceVersion,
		},
	}
	ir.Status = recv.computeStatus(ingress)
	return ir
}

func (recv *IRHandler) computeStatus(ingress *xlate.Ingress) Status {
	status := Status{}
	if ingress.Valid() {
		status.CurrentStatus = constants.StatusValid
		status.Description = constants.StatusValid + " IngressRoute"
	} else {
		status.CurrentStatus = constants.StatusInvalid
		if ingress.ValidationError == "" {
			status.Description = ingress.CRDError
		} else {
			status.Description = ingress.ValidationError
		}
	}
	return status
}
