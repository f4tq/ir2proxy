package v1

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/constants/annotations"
	"kapcom.adobe.com/envoy_api"
	"kapcom.adobe.com/types"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xlate"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	corsRe = "^[a-zA-Z0-9!#$%&'*+.^_`|~-]+$"
	// used for LoadBalancy Policy 'Cookie'
	SessionCookie = "X-Contour-Session-Affinity"
)

var (
	corsHeaderRe *regexp.Regexp
)

func init() {
	corsHeaderRe, _ = regexp.Compile(corsRe)
}

// This can not change with the introduction of the EnvoySidecar CRD
const IngressTypeURL = "contour.heptio.com/v1/HTTPProxy"

type HPHandler struct {
	handler cache.ResourceEventHandler
	xlate.IngressStatus
}

func HTTPProxyHandler(handler cache.ResourceEventHandler) cache.ResourceEventHandler {
	return &HPHandler{
		handler: handler,
	}
}

// defined so that the deep copy generator skips it
func (in *HPHandler) DeepCopy() *HPHandler {
	if in == nil {
		return nil
	}
	out := new(HPHandler)
	return out
}

func (recv *HPHandler) OnAdd(iface interface{}) {
	if crd, ok := iface.(*HTTPProxy); ok {
		iface = recv.CRDToIngress(crd)
	}
	recv.handler.OnAdd(iface)
}

func (recv *HPHandler) OnUpdate(old, new interface{}) {
	if oldCRD, ok := old.(*HTTPProxy); ok {
		old = recv.CRDToIngress(oldCRD)
		new = recv.CRDToIngress(new.(*HTTPProxy))
	}
	recv.handler.OnUpdate(old, new)
}

func (recv *HPHandler) OnDelete(iface interface{}) {
	if crd, ok := iface.(*HTTPProxy); ok {
		iface = recv.CRDToIngress(crd)
	}
	recv.handler.OnDelete(iface)
}

// HTTPPRoxy, unlike IngressRoute, bundles much of the information
// at the Route and TCPProxy layer, that makes translating from
// Service to Cluster to require additional information to be passed in
func serviceToCluster(service *Service, addlInfo interface{}) (xlate.Cluster, error) {
	c := xlate.Cluster{}
	c.Name = service.Name
	c.Port = int32(service.Port)
	c.Weight = service.Weight
	var err error

	// The validation of the LoadBalancerPolicy should differ between
	// the one defined on an TCPProxy and one defined on a Route, because certain
	// policies aren't defined on services behind a TCPProxy
	if tcpProxy, ok := addlInfo.(*TCPProxy); ok {
		if tcpProxy.LoadBalancerPolicy != nil &&
			contains(tcpProxy.LoadBalancerPolicy.Strategy, []string{"RequestHash", "Cookie"}) {
			return c, fmt.Errorf("tcpproxy does not support loadbalancing policy %s", tcpProxy.LoadBalancerPolicy.Strategy)
		}
		err = addLBStrategyToCluster(&c, tcpProxy.LoadBalancerPolicy, tcpProxy.LeastRequestLbConfig)
	} else if route, ok := addlInfo.(*Route); ok {
		err = addLBStrategyToCluster(&c, route.LoadBalancerPolicy, route.LeastRequestLbConfig)
		addHealthCheckToCluster(&c, route.HealthCheckPolicy)
	}
	return c, err
}

func addLBStrategyToCluster(c *xlate.Cluster, lbpolicy *LoadBalancerPolicy, leastRequestConfig *LeastRequestLbConfig) error {
	if lbpolicy == nil {
		return nil
	}

	switch lbpolicy.Strategy {
	case "WeightedLeastRequest":
		c.LbPolicy = cluster.Cluster_LEAST_REQUEST
		if leastRequestConfig != nil {
			choiceCount := leastRequestConfig.ChoiceCount
			if choiceCount < 2 {
				return errors.New("choiceCount out of range; allowed values are between 2 and 100")
			} else if choiceCount > 100 {
				// value 100 is too big, leave it for testing purposes,
				// ToDo: reduce to max 20.
				return errors.New("choiceCount out of range; allowed values are between 2 and 100")
			}
			c.LeastRequestLbConfig = &xlate.LeastRequestLbConfig{ChoiceCount: leastRequestConfig.ChoiceCount}
		}
	case "Random":
		c.LbPolicy = cluster.Cluster_RANDOM
	case "Cookie":
		if len(lbpolicy.RequestHashPolicies) != 0 {
			return errors.New("policy Cookie accepts no RequestHashPolies")
		}
		// per upstream-> RR
		c.LbPolicy = cluster.Cluster_ROUND_ROBIN
	case "RequestHash":
		if len(lbpolicy.RequestHashPolicies) == 0 {
			return errors.New("policy RequestHash chosen but no policies provided")
		}
		// per upstream -> RR
		c.LbPolicy = cluster.Cluster_ROUND_ROBIN

	// should figure out what to do when RequestHash is specified
	// Moreover the HTTPProxy specs don't explicitly mention
	// "RingHash" and "Maglev" as valid values for an HTTP request
	// It's unclear as to why that's the case, especially since
	// Envoy does seem to continue supporting them
	case "RingHash":
		c.LbPolicy = cluster.Cluster_RING_HASH
	case "Maglev":
		c.LbPolicy = cluster.Cluster_MAGLEV
	default: // includes explicit RoundRobin
		c.LbPolicy = cluster.Cluster_ROUND_ROBIN
	}

	return nil
}

func addHealthCheckToCluster(c *xlate.Cluster, hc *HTTPHealthCheckPolicy) {
	if hc == nil {
		return
	}

	c.HealthCheck = &xlate.HealthCheck{
		Path:               hc.Path,
		Host:               hc.Host,
		Timeout:            time.Duration(hc.TimeoutSeconds) * time.Second,
		Interval:           time.Duration(hc.IntervalSeconds) * time.Second,
		UnhealthyThreshold: hc.UnhealthyThresholdCount,
		HealthyThreshold:   hc.HealthyThresholdCount,
	}
}

func extractHeaderMatcher(conditions []Condition) (string, []xlate.HeaderMatcher, error) {
	// A single prefix must be present
	if conditions == nil {
		return "", nil, errors.New("No header matching info was provided")
	}
	matchPrefix := ""
	headerMatchers := make([]xlate.HeaderMatcher, 0)
	for _, cond := range conditions {
		if cond.Header != nil && cond.Prefix != "" {
			err := errors.New("Condition can not have both: a Prefix and a HeaderCondition")
			return matchPrefix, nil, err
		}
		if matchPrefix != "" && cond.Prefix != "" {
			err := errors.New("Matcher for Route has multiple prefixes")
			return matchPrefix, nil, err
		}
		if matchPrefix == "" {
			// set the prefix match for the delegated route
			matchPrefix = cond.Prefix
		}
		if cond.Header != nil {
			presentPtr := new(bool)
			*presentPtr = cond.Header.Present
			hm := xlate.HeaderMatcher{
				Name:        cond.Header.Name,
				Present:     presentPtr,
				Contains:    cond.Header.Contains,
				NotContains: cond.Header.NotContains,
				Exact:       cond.Header.Exact,
				NotExact:    cond.Header.NotExact,
			}
			headerMatchers = append(headerMatchers, hm)
		}
	}
	return matchPrefix, headerMatchers, nil
}

// contains -  check where string is in list
func contains(item string, list []string) bool {
	for _, ii := range list {
		if ii == item {
			return true
		}
	}
	return false
}
func validateRatelimitPolicy(policy *RateLimitPolicy) error {
	// See https://projectcontour.io/docs/v1.15.2/config/rate-limiting/#defining-a-global-rate-limit-policy
	// and https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-msg-config-route-v3-ratelimit
	if policy.Global == nil {
		return errors.New("is empty")
	}
	if len(policy.Global.Descriptors) == 0 {
		return errors.New("has zero Global descriptors")
	}

	for _, descriptor := range policy.Global.Descriptors {
		if len(descriptor.Entries) == 0 {
			return errors.New("descriptor has zero entries")
		}

		for _, entry := range descriptor.Entries {
			if entry.GenericKey == nil &&
				entry.RemoteAddress == nil &&
				entry.RequestHeader == nil &&
				entry.RequestHeaderValueMatch == nil {
				return errors.New("need one of generickey, remoteaddress,requestheader or requestheader")
			}
			if entry.GenericKey != nil {
				// must be one of
				if entry.GenericKey.Value == "" {
					return errors.New("generickey must have value")

				}
				if entry.GenericKey.Key == "" {
					entry.GenericKey.Key = "generic-key"
				}
			}
			// ok

			if entry.RequestHeaderValueMatch != nil {
				rq := entry.RequestHeaderValueMatch
				if rq.Value == "" {
					return errors.New("header value match value must be defined")
				} else if len(rq.Headers) == 0 {
					return errors.New("header value match must have non-zero list of headers")
				}
				for _, v := range rq.Headers {
					if v.Name == "" {
						return errors.New("header value match header must have name")
					}
					// ok
				}
			}
			if entry.RequestHeader != nil {
				rq := entry.RequestHeader
				if rq.HeaderName == "" {
					return errors.New("request header name must have a value")
				}
				if rq.DescriptorKey == "" {
					return errors.New("request header descriptor key must have a value")
				}
				//ok
			}
		}
	}
	return nil
}

//func CrdToRatelimt(rd.Spec.VirtualHost.RateLimitPolicy)
func CrdToRateLimit(policy *RateLimitPolicy) ([]*envoy_api.RateLimit, error) {
	rateLimits := make([]*envoy_api.RateLimit, len(policy.Global.Descriptors))
	ref := policy.Global.Descriptors
	for ii, descriptor := range ref {
		pol := envoy_api.NewRateLimit()
		pol.Actions = make([]*route.RateLimit_Action, 0)
		for _, entry := range descriptor.Entries {

			if entry.GenericKey != nil {
				action := route.RateLimit_Action{}

				action.ActionSpecifier = &route.RateLimit_Action_GenericKey_{
					GenericKey: &route.RateLimit_Action_GenericKey{
						DescriptorValue: entry.GenericKey.Value,
					},
				}
				pol.Actions = append(pol.Actions, &action)
			}
			if entry.RemoteAddress != nil {
				action := route.RateLimit_Action{}

				action.ActionSpecifier = &route.RateLimit_Action_RemoteAddress_{
					RemoteAddress: &route.RateLimit_Action_RemoteAddress{},
				}
				pol.Actions = append(pol.Actions, &action)
			}
			if entry.RequestHeader != nil {
				action := route.RateLimit_Action{}

				action.ActionSpecifier = &route.RateLimit_Action_RequestHeaders_{
					RequestHeaders: &route.RateLimit_Action_RequestHeaders{
						HeaderName:    entry.RequestHeader.HeaderName,
						DescriptorKey: entry.RequestHeader.DescriptorKey,
					},
				}
				pol.Actions = append(pol.Actions, &action)
			}
			if entry.RequestHeaderValueMatch != nil {
				action := route.RateLimit_Action{}

				hv := &route.RateLimit_Action_HeaderValueMatch_{
					HeaderValueMatch: &route.RateLimit_Action_HeaderValueMatch{
						DescriptorValue: entry.RequestHeaderValueMatch.Value,
						ExpectMatch:     wrapperspb.Bool(entry.RequestHeaderValueMatch.ExpectMatch),
					},
				}
				hv.HeaderValueMatch.Headers = make([]*route.HeaderMatcher, len(entry.RequestHeaderValueMatch.Headers))

				for ii, header := range entry.RequestHeaderValueMatch.Headers {
					hh := route.HeaderMatcher{
						Name: header.Name,
					}
					switch {
					case header.Contains != "":
						hh.HeaderMatchSpecifier = &route.HeaderMatcher_SafeRegexMatch{
							SafeRegexMatch: &matcher.RegexMatcher{
								EngineType: &matcher.RegexMatcher_GoogleRe2{
									GoogleRe2: &matcher.RegexMatcher_GoogleRE2{},
								},
								Regex: fmt.Sprintf(".*%s.*", header.Contains),
							},
						}
					case header.NotContains != "":
						hh.HeaderMatchSpecifier = &route.HeaderMatcher_SafeRegexMatch{
							SafeRegexMatch: &matcher.RegexMatcher{
								EngineType: &matcher.RegexMatcher_GoogleRe2{
									GoogleRe2: &matcher.RegexMatcher_GoogleRE2{},
								},
								Regex: fmt.Sprintf(".*%s.*", header.NotContains),
							},
						}
						hh.InvertMatch = true
					case header.Exact != "":
						hh.HeaderMatchSpecifier = &route.HeaderMatcher_ExactMatch{
							ExactMatch: header.Exact,
						}
					case header.NotExact != "":
						hh.HeaderMatchSpecifier = &route.HeaderMatcher_ExactMatch{
							ExactMatch: header.Exact,
						}
						hh.InvertMatch = true

					case header.Present:
						hh.HeaderMatchSpecifier = &route.HeaderMatcher_PresentMatch{
							PresentMatch: true,
						}

					}
					hv.HeaderValueMatch.Headers[ii] = &hh
				}
				action.ActionSpecifier = hv
				pol.Actions = append(pol.Actions, &action)
			}
		}
		rateLimits[ii] = pol
	}
	return rateLimits, nil
}

func (recv *HPHandler) CRDToIngress(crd *HTTPProxy) *xlate.Ingress {
	var err error
	ingress := &xlate.Ingress{
		Name:      crd.Name,
		Namespace: crd.Namespace,
		TypeURL:   IngressTypeURL,
		Priority:  2,
	}

	if crd.Annotations == nil {
		ingress.CRDError = "Missing annotations"
	} else {
		ingress.Class = crd.Annotations[annotations.IC]
		if ingress.Class == "" {
			ingress.CRDError = "Missing or empty " + annotations.IC + " annotation"
		}

		ingress.ServiceId = crd.Annotations[annotations.ServiceId]

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

			if crd.Spec.VirtualHost.Authorization != nil {
				switch {
				case !xlate.AuthzEnabled():
					ingress.CRDError = "Authorization is not enabled"
					return ingress
				case crd.Spec.VirtualHost.Authorization.AuthPolicy == nil:
					ingress.CRDError = "Authorization requires an auth policy"
					return ingress
				}
				auth := new(xlate.AuthorizationServer)

				auth.FailOpen = crd.Spec.VirtualHost.Authorization.FailOpen
				dur, err := time.ParseDuration(crd.Spec.VirtualHost.Authorization.ResponseTimeout)
				if err != nil {
					ingress.CRDError = "Authorization ResponseTimeout must be in time.Duration format"
					return ingress
				}
				auth.ResponseTimeout = dur

				pp := new(xlate.AuthorizationPolicy)
				pp.Disabled = crd.Spec.VirtualHost.Authorization.AuthPolicy.Disabled
				pp.Context = make(map[string]string)
				for k, v := range crd.Spec.VirtualHost.Authorization.AuthPolicy.Context {
					pp.Context[k] = v
				}
				auth.AuthPolicy = pp
				ingress.VirtualHost.Authorization = auth
			}

		} else {
			if crd.Spec.VirtualHost.Authorization != nil {
				ingress.CRDError = "virtualhost tls must be enabled to use Authorization"
				return ingress
			}
		}
		if crd.Spec.VirtualHost.RateLimitPolicy != nil {
			err := validateRatelimitPolicy(crd.Spec.VirtualHost.RateLimitPolicy)
			if err != nil {
				ingress.CRDError = fmt.Sprintf("virtualhost ratelimit policy failed %s", err.Error())
				return ingress
			} else {
				ingress.VirtualHost.RateLimits, err = CrdToRateLimit(crd.Spec.VirtualHost.RateLimitPolicy)
				if err != nil {
					ingress.CRDError = fmt.Sprintf("virtual ratelimit policy conversion failed %s", err.Error())
					return ingress
				}
			}
		}
		if crd.Spec.VirtualHost.CORSPolicy != nil {
			pol := crd.Spec.VirtualHost.CORSPolicy
			switch {
			case len(pol.AllowHeaders) == 0:
				ingress.CRDError = "cors policy requires AllowHedaders list"
				return ingress
			case len(pol.AllowOrigin) == 0:
				ingress.CRDError = "cors policy requires AllowOrigin list "
				return ingress
			default:
				for _, ii := range pol.AllowHeaders {
					if !corsHeaderRe.MatchString((string)(ii)) {
						ingress.CRDError = fmt.Sprintf("AllowedHeader %s must match %s ", (string)(ii), corsRe)
						return ingress
					}
				}
				for _, ii := range pol.AllowMethods {
					if !corsHeaderRe.MatchString((string)(ii)) {
						ingress.CRDError = fmt.Sprintf("AllowedMethods %s must match %s", (string)(ii), corsRe)
						return ingress
					}
				}
				for _, ii := range pol.ExposeHeaders {
					if !corsHeaderRe.MatchString((string)(ii)) {
						ingress.CRDError = fmt.Sprintf("ExposeHeaders %s must match %s", (string)(ii), corsRe)
						return ingress
					}
				}
			}
			cpol := &envoy_api.CorsPolicy{
				CorsPolicy: route.CorsPolicy{},
			}
			methods := make([]string, len(pol.AllowMethods))
			for idx, ii := range pol.AllowMethods {
				methods[idx] = (string)(ii)
			}
			headers := make([]string, len(pol.AllowHeaders))
			for idx, ii := range pol.AllowHeaders {
				headers[idx] = (string)(ii)
			}
			exposeheaders := make([]string, len(pol.ExposeHeaders))
			for idx, ii := range pol.ExposeHeaders {
				exposeheaders[idx] = (string)(ii)
			}
			origins := make([]*matcher.StringMatcher, len(pol.AllowOrigin))
			for idx, ii := range pol.AllowOrigin {
				origins[idx] = &matcher.StringMatcher{
					MatchPattern: &matcher.StringMatcher_Exact{
						Exact: ii,
					},
				}

			}
			cpol.AllowHeaders = strings.Join(headers, ",")
			cpol.AllowMethods = strings.Join(methods, ",")
			cpol.ExposeHeaders = strings.Join(exposeheaders, ",")
			cpol.AllowOriginStringMatch = origins
			if pol.MaxAge != "" {
				d, err := time.ParseDuration(pol.MaxAge)
				if err != nil {
					ingress.CRDError = fmt.Sprintf("unable to parse timeout string %q: %s", pol.MaxAge, err)
					return ingress
				}
				if d < 0 {
					ingress.CRDError = fmt.Sprintf("Maxage cannot be less than zero %q", pol.MaxAge)
					return ingress
				}
				cpol.MaxAge = pol.MaxAge
			} else {
				cpol.MaxAge = ""
			}
			cpol.AllowCredentials = wrapperspb.Bool(pol.AllowCredentials)
			ingress.VirtualHost.Cors = cpol
		}

		ingress.VirtualHost.Logging = crd.Spec.VirtualHost.Logging
	}

	if crd.Spec.TCPProxy != nil {
		if len(crd.Spec.TCPProxy.Services) == 0 && crd.Spec.TCPProxy.Include == nil {
			ingress.CRDError = "TCPProxy has no Services"
		} else if len(crd.Spec.TCPProxy.Services) > 0 && crd.Spec.TCPProxy.Include != nil {
			ingress.CRDError = "TCPProxy: it is invalid to proxy to a service and delegate to: " + crd.Spec.TCPProxy.Include.Name + " in namespace: " + crd.Spec.TCPProxy.Include.Namespace
		} else if crd.Spec.TCPProxy.Include != nil {
			// TODO(lev) add support for TCPProxy delegation
			ingress.CRDError = "TCPProxy wants to delegate to: " + crd.Spec.TCPProxy.Include.Name + " in namespace: " + crd.Spec.TCPProxy.Include.Namespace
		} else {
			ingress.Listener.TCPProxy = &xlate.TCPProxy{
				Clusters: make([]xlate.Cluster, len(crd.Spec.TCPProxy.Services)),
			}
			for i, service := range crd.Spec.TCPProxy.Services {
				ingress.Listener.TCPProxy.Clusters[i], err = serviceToCluster(&service, crd.Spec.TCPProxy)
				if err != nil {
					ingress.CRDError = err.Error()
					return ingress
				}
			}
		}
	}

	routesLen := len(crd.Spec.Routes) + len(crd.Spec.Includes)
	if routesLen == 0 {
		if crd.Spec.TCPProxy == nil {
			ingress.CRDError = "Missing routes and tcpproxy"
		}
	} else {
		ingress.VirtualHost.Routes = make([]*xlate.Route, 0, routesLen)
	}
	// route validation moved to xlate package
	for _, route := range crd.Spec.Routes {
		if len(route.Services) == 0 && route.Redirect == nil {
			ingress.CRDError = "Route has no Services or Redirect"
			continue
		}

		if len(route.Services) > 0 && route.Redirect != nil {
			ingress.CRDError = "Route has both Services and Redirect"
			continue
		}

		// A single prefix must be present
		matchPrefix, headerMatchers, err := extractHeaderMatcher(route.Conditions)
		if err != nil {
			ingress.CRDError = err.Error()
			continue
		}

		xRoute := new(xlate.Route)
		xRoute.Match = matchPrefix
		// HTTPProxy does not support PrefixRewrite
		// partial support for now - only what IngressRoute supports
		if prp := route.PathRewritePolicy; prp != nil && len(prp.ReplacePrefix) > 0 {
			xRoute.PrefixRewrite = prp.ReplacePrefix[0].Replacement
		}
		xRoute.WebsocketUpgrade = route.EnableWebsockets
		xRoute.HTTPSRedirect = !route.PermitInsecure
		xRoute.HeaderMatchers = headerMatchers

		if route.RetryPolicy != nil {
			xRoute.RetryPolicy = &xlate.RetryPolicy{
				NumRetries:    route.RetryPolicy.NumRetries,
				PerTryTimeout: route.RetryPolicy.PerTryTimeout,
			}
		}

		if route.TimeoutPolicy != nil {
			// Contour allows to specify an infinite timeout here
			// https://github.com/projectcontour/contour/blob/v1.8.1/internal/timeout/timeout.go#L57-L63
			// https://www.envoyproxy.io/docs/envoy/v1.15.0/api-v3/config/route/v3/route_components.proto#envoy-v3-api-field-config-route-v3-routeaction-timeout
			if route.TimeoutPolicy.Response == "infinity" {
				xRoute.Timeout = -1
			} else if route.TimeoutPolicy.Response != "" {
				d, _ := time.ParseDuration(route.TimeoutPolicy.Response)
				if d > 0 {
					xRoute.Timeout = d
				} else {
					ingress.CRDError = "invalid Route timeout"
					continue
				}
			}
			if route.TimeoutPolicy.Idle == "infinity" {
				xRoute.IdleTimeout = -1
			} else if route.TimeoutPolicy.Idle != "" {
				idle, _ := time.ParseDuration(route.TimeoutPolicy.Idle)
				if idle > 0 {
					xRoute.IdleTimeout = idle
				} else {
					ingress.CRDError = "invalid Route idle timeout"
					continue
				}
			}
		}
		xRoute.PerFilterConfig = route.PerFilterConfig
		if route.AuthPolicy != nil {
			// if the AuthPolicy is Disable. should this be an error?
			//   i.e. Vhost defined in one ns with auth on, namespace delegate can turn it off.

			if !xlate.AuthzEnabled() {
				ingress.CRDError = "Route references AuthPolicy but auth is not enabled"
				return ingress
			}
			if crd.Spec.VirtualHost != nil {
				// can verify some routes is we have the vhost.  others need to wait for more context
				switch {
				case crd.Spec.VirtualHost.Authorization == nil:
					ingress.CRDError = fmt.Sprintf("Route references AuthPolicy but auth is not enabled for this VirtualHost %s", crd.Spec.VirtualHost.Fqdn)
					return ingress
				case crd.Spec.VirtualHost.TLS == nil:
					ingress.CRDError = fmt.Sprintf("Route references AuthPolicy but TLS is not enabled for %s", crd.Spec.VirtualHost.Fqdn)
					return ingress
				}
			}
			if xRoute.PerFilterConfig == nil {
				xRoute.PerFilterConfig = &xlate.PerFilterConfig{}
			}
			var pf = xRoute.PerFilterConfig
			// route AuthPolicy can either be Disabled OR provide a context but not both
			if route.AuthPolicy.Disabled {
				pf.Authz = &xlate.ExtAuthzPerRoute{
					ExtAuthzPerRoute: ext_authz.ExtAuthzPerRoute{
						Override: &ext_authz.ExtAuthzPerRoute_Disabled{
							Disabled: true,
						},
					},
				}
			} else {
				// allow an empty context to blot out the virtual host level context
				mp := map[string]string{}
				if route.AuthPolicy.Context != nil {
					// make a copy
					for k, v := range route.AuthPolicy.Context {
						mp[k] = v
					}
				}
				pf.Authz = &xlate.ExtAuthzPerRoute{
					ExtAuthzPerRoute: ext_authz.ExtAuthzPerRoute{
						Override: &ext_authz.ExtAuthzPerRoute_CheckSettings{
							CheckSettings: &ext_authz.CheckSettings{
								ContextExtensions: mp,
							},
						},
					},
				}
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
		if route.RateLimitPolicy != nil && route.RateLimitPolicy.Global != nil {
			err := validateRatelimitPolicy(route.RateLimitPolicy)
			if err != nil {
				ingress.CRDError = fmt.Sprintf("route level policy failed %s", err)
				continue
			}
			xRoute.RateLimits, err = CrdToRateLimit(route.RateLimitPolicy)
			if err != nil {
				ingress.CRDError = fmt.Sprintf("route ratelimit policy conversion failed %s", err.Error())
			}

		}
		xRoute.HashPolicies, err = handleStickyPolicy(&route)
		if err != nil {
			ingress.CRDError = err.Error()
			return ingress
		}

		xRoute.Clusters = make([]xlate.Cluster, len(route.Services))
		for i, service := range route.Services {
			xRoute.Clusters[i], err = serviceToCluster(&service, &route)
			if err != nil {
				ingress.CRDError = err.Error()
				return ingress
			}
		}

		if route.Redirect != nil {
			xRoute.Redirect = route.Redirect
		}

		ingress.VirtualHost.Routes = append(ingress.VirtualHost.Routes, xRoute)
	}

	// Route validation that can be done commonly across CRDs takes place in
	// xlate.Validate()
	// TODO(lev) add validations that exclude routes with HeaderMatcher values
	// showing up elsewhere, either in another Include or in another Route
	for _, delegatedRoute := range crd.Spec.Includes {
		// A single prefix must be present
		matchPrefix, headerMatchers, err := extractHeaderMatcher(delegatedRoute.Conditions)
		if err != nil {
			ingress.CRDError = err.Error()
			continue
		}

		xRoute := new(xlate.Route)
		xRoute.Match = matchPrefix
		// PrefixRewrite is not supported in the version of HTTPProxy presently being introduced to KAPCOM
		xRoute.HeaderMatchers = headerMatchers
		xRoute.Delegate = &xlate.Delegate{
			Name:      delegatedRoute.Name,
			Namespace: delegatedRoute.Namespace,
		}
		// What HTTPProxy calls "Includes" is called "Delegate" in xlate
		// However, note that while HTTPProxy models delegetad routes as Includes,
		// and keeps them separate from Routes defined to a service, xlate and
		// IngressRoute model them as one as an xRoute, keeping both types together in one slice.
		ingress.VirtualHost.Routes = append(ingress.VirtualHost.Routes, xRoute)
	}

	ingress.ResourceVersion = crd.ResourceVersion
	ingress.LastCRDStatus = crd.Status.Description

	return ingress
}

// handleStickyPolicy --
func handleStickyPolicy(route *Route) ([]xlate.HashPolicy, error) {
	if route.LoadBalancerPolicy != nil {
		switch route.LoadBalancerPolicy.Strategy {
		case "Cookie":
			// per upstream v1.19 internal/dag/policy.go#642 , hard-wire the cookie.
			forever := time.Duration(0)
			hash := make([]xlate.HashPolicy, 1)
			hash[0] = xlate.HashPolicy{
				Cookie: &xlate.HashPolicyCookie{
					Name: SessionCookie,
					Ttl:  &forever,
					Path: "/",
				},
				Terminal: true,
			}
			return hash, nil
		case "RequestHash":
			// upstream RequestHash allows for multiple headers but no access to ttl/path
			hash := make([]xlate.HashPolicy, len(route.LoadBalancerPolicy.RequestHashPolicies))
			mp := make(map[string]bool)
			for ii, hp := range route.LoadBalancerPolicy.RequestHashPolicies {
				if hp.HeaderHashOptions == nil {
					return nil, fmt.Errorf("missing RequestHash.HeaderHashOptions in item %d", ii)
				}
				if len(hp.HeaderHashOptions.HeaderName) == 0 {
					return nil, fmt.Errorf("missing RequestHash.HeaderHashOptions.HeaderName must be defined in item %d", ii)
				}
				_, ok := mp[hp.HeaderHashOptions.HeaderName]
				if ok {
					return nil, fmt.Errorf("duplicate header name %s RequestHash.HeaderHashOptions.HeaderName in item %d",
						hp.HeaderHashOptions.HeaderName, ii)
				}
				tt := new(types.Duration)
				// again, upstream provides no access to ttl/path
				newPol := xlate.HashPolicy{
					Cookie: &xlate.HashPolicyCookie{
						Name: hp.HeaderHashOptions.HeaderName,
						Ttl:  &tt.Duration,
						Path: "/",
					},
					Terminal: hp.Terminal,
				}
				hash[ii] = newPol
				mp[hp.HeaderHashOptions.HeaderName] = true
			}
			return hash, nil
		}
	}
	// otherwise, make the hashes that may apply later
	hash := make([]xlate.HashPolicy, len(route.HashPolicy))
	for ii, hp := range route.HashPolicy {
		if hp.Header != nil {
			hash[ii] = xlate.HashPolicy{
				Header: &xlate.HashPolicyHeader{
					Name: hp.Header.HeaderName,
				},
			}
		} else if hp.ConnectionProperties != nil {
			hash[ii] = xlate.HashPolicy{
				ConnectionProperties: &xlate.HashPolicyConnectionProperties{
					SourceIp: hp.ConnectionProperties.SourceIp,
				},
			}
		} else if hp.Cookie != nil {
			var tt *types.Duration
			tt = hp.Cookie.Ttl
			if tt == nil {
				tt = new(types.Duration)
			}
			hash[ii] = xlate.HashPolicy{
				Cookie: &xlate.HashPolicyCookie{
					Name: hp.Cookie.Name,
					Ttl:  &tt.Duration,
					Path: hp.Cookie.Path,
				},
				Terminal: hp.Terminal,
			}
		}
	}
	return hash, nil
}

func HTTPProxyStatusInterface() xlate.IngressStatus {
	return &HPHandler{}
}

func (recv *HPHandler) Type() string {
	return IngressTypeURL
}

func (recv *HPHandler) StatusChanged(ingress *xlate.Ingress) (bool, string) {
	newStatus := recv.computeStatus(ingress)
	return ingress.LastCRDStatus != newStatus.Description, newStatus.Description
}

func (recv *HPHandler) PrepareForStatusUpdate(ingress *xlate.Ingress) interface{} {
	hp := &HTTPProxy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ingress.Namespace,
			Name:            ingress.Name,
			ResourceVersion: ingress.ResourceVersion,
		},
	}
	hp.Status = recv.computeStatus(ingress)
	return hp
}

func (recv *HPHandler) computeStatus(ingress *xlate.Ingress) Status {
	status := Status{}
	if ingress.Valid() {
		status.CurrentStatus = constants.StatusValid
		status.Description = constants.StatusValid + " HTTPProxy"
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
