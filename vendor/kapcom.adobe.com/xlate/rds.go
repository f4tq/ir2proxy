package xlate

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/set"
	"kapcom.adobe.com/util"
	"kapcom.adobe.com/xds"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	header_to_metadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/inconshreveable/log15.v2"
	k8s "k8s.io/api/core/v1"
)

type VhostByName []*route.VirtualHost

func (recv VhostByName) Len() int {
	return len(recv)
}
func (recv VhostByName) Less(i, j int) bool {
	return recv[i].Name < recv[j].Name
}
func (recv VhostByName) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

type WeightedClustersByName []*route.WeightedCluster_ClusterWeight

func (recv WeightedClustersByName) Len() int {
	return len(recv)
}
func (recv WeightedClustersByName) Less(i, j int) bool {
	return recv[i].Name < recv[j].Name
}
func (recv WeightedClustersByName) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

type RouteByLength []*route.Route

func (recv RouteByLength) Len() int {
	return len(recv)
}
func (recv RouteByLength) Less(i, j int) bool {
	switch ri := recv[i].Match.PathSpecifier.(type) {
	case *route.RouteMatch_Prefix:
		switch rj := recv[j].Match.PathSpecifier.(type) {
		case *route.RouteMatch_Prefix:
			if ri.Prefix == rj.Prefix {
				return compareHeaderMatchers(recv[i].Match.Headers, recv[j].Match.Headers)
			}
			// same length prefixes need to sort consistently
			if len(ri.Prefix) == len(rj.Prefix) {
				return ri.Prefix < rj.Prefix
			}
			return len(ri.Prefix) > len(rj.Prefix) // longest first
		case *route.RouteMatch_Path:
			return false // exact first
		default:
			return true
		}
	case *route.RouteMatch_Path:
		switch rj := recv[j].Match.PathSpecifier.(type) {
		case *route.RouteMatch_Path:
			if ri.Path == rj.Path {
				return compareHeaderMatchers(recv[i].Match.Headers, recv[j].Match.Headers)
			}
			return ri.Path < rj.Path
		case *route.RouteMatch_Prefix:
			return true // exact first
		default:
			return true
		}
	default:
		return true
	}
}
func (recv RouteByLength) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

type HeaderMatcherByLength []*route.HeaderMatcher

func (recv HeaderMatcherByLength) Len() int {
	return len(recv)
}
func (recv HeaderMatcherByLength) Less(i, j int) bool {
	if recv[i].Name == recv[j].Name {
		// "exact" > "regex" > "present"
		switch ri := recv[i].HeaderMatchSpecifier.(type) {
		case *route.HeaderMatcher_PresentMatch:
			switch recv[j].HeaderMatchSpecifier.(type) {
			case *route.HeaderMatcher_PresentMatch:
				// "present" wins over "not present"
				return !recv[i].InvertMatch
			case *route.HeaderMatcher_SafeRegexMatch:
				return false
			case *route.HeaderMatcher_ExactMatch:
				return false
			}
		case *route.HeaderMatcher_SafeRegexMatch:
			switch rj := recv[j].HeaderMatchSpecifier.(type) {
			case *route.HeaderMatcher_PresentMatch:
				return true
			case *route.HeaderMatcher_SafeRegexMatch:
				if ri.SafeRegexMatch.Regex == rj.SafeRegexMatch.Regex {
					// regex "match" wins over regex "not match"
					return !recv[i].InvertMatch
				}
				// longest first
				return len(ri.SafeRegexMatch.Regex) > len(rj.SafeRegexMatch.Regex)
			case *route.HeaderMatcher_ExactMatch:
				return false
			}
		case *route.HeaderMatcher_ExactMatch:
			switch rj := recv[j].HeaderMatchSpecifier.(type) {
			case *route.HeaderMatcher_PresentMatch:
				return true
			case *route.HeaderMatcher_SafeRegexMatch:
				return true
			case *route.HeaderMatcher_ExactMatch:
				if ri.ExactMatch == rj.ExactMatch {
					// "exact" wins over "not exact"
					return !recv[i].InvertMatch
				}
				// longest first
				return len(ri.ExactMatch) > len(rj.ExactMatch)
			}
		}
	}
	return recv[i].Name < recv[j].Name
}
func (recv HeaderMatcherByLength) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

// Given 2 lists of header matchers, returns true if the first one is more
// significant (from a matching standpoint) than the second one
func compareHeaderMatchers(hm1, hm2 []*route.HeaderMatcher) bool {
	if len(hm1) == len(hm2) {
		// sort both, then compare 1 by 1
		sort.Stable(HeaderMatcherByLength(hm1))
		sort.Stable(HeaderMatcherByLength(hm2))
		for z := 0; z < len(hm1); z++ {
			head2head := []*route.HeaderMatcher{
				hm1[z],
				hm2[z],
			}
			if HeaderMatcherByLength(head2head).Less(0, 1) {
				return true
			}
		}
		// default head to head compare
		return false
	}
	// More headers wins
	return len(hm1) > len(hm2)
}

func perFilterConfig(log log15.Logger, vhRoute *route.Route, xRoute *Route) {
	if xRoute.PerFilterConfig == nil {
		return
	}

	if xRoute.PerFilterConfig.IpAllowDeny != nil {
		if vhRoute.TypedPerFilterConfig == nil {
			vhRoute.TypedPerFilterConfig = make(map[string]*any.Any)
		}

		bs, _ := json.Marshal(xRoute.PerFilterConfig.IpAllowDeny)
		spb := new(structpb.Struct)
		spb.UnmarshalJSON(bs)

		vhRoute.TypedPerFilterConfig[constants.IpAllowDenyFilter] = util.ToAny(log, spb)
	}

	if xRoute.PerFilterConfig.HeaderSize != nil {
		if vhRoute.TypedPerFilterConfig == nil {
			vhRoute.TypedPerFilterConfig = make(map[string]*any.Any)
		}

		bs, _ := json.Marshal(xRoute.PerFilterConfig.HeaderSize)
		spb := new(structpb.Struct)
		spb.UnmarshalJSON(bs)

		vhRoute.TypedPerFilterConfig[constants.HeaderSizeFilter] = util.ToAny(log, spb)
	}

	if authz := xRoute.PerFilterConfig.Authz; authz != nil {
		if vhRoute.TypedPerFilterConfig == nil {
			vhRoute.TypedPerFilterConfig = make(map[string]*any.Any)
		}

		vhRoute.TypedPerFilterConfig[wellknown.HTTPExternalAuthorization] = util.ToAny(log, &authz.ExtAuthzPerRoute)
	}
}

func headerMatchers(vhRoute *route.Route, xRoute *Route) {
	for _, xHeaderMatcher := range xRoute.HeaderMatchers {
		hm := &route.HeaderMatcher{
			Name: xHeaderMatcher.Name,
		}

		switch {
		case xHeaderMatcher.Present != nil:
			hm.HeaderMatchSpecifier = &route.HeaderMatcher_PresentMatch{
				PresentMatch: true,
			}
			// Can't do `PresentMatch: false`!
			if !*xHeaderMatcher.Present {
				hm.InvertMatch = true
			}
		case xHeaderMatcher.Contains != "":
			// TODO(lrouquet): possibly replace with HeaderMatcher_ContainsMatch (Envoy 1.16)
			hm.HeaderMatchSpecifier = &route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &matcher.RegexMatcher{
					EngineType: &matcher.RegexMatcher_GoogleRe2{
						GoogleRe2: &matcher.RegexMatcher_GoogleRE2{},
					},
					// https://www.envoyproxy.io/docs/envoy/v1.15.2/api-v3/config/route/v3/route_components.proto#envoy-v3-api-field-config-route-v3-headermatcher-safe-regex-match
					Regex: fmt.Sprintf(".*%s.*", regexp.QuoteMeta(xHeaderMatcher.Contains)),
				},
			}
		case xHeaderMatcher.NotContains != "":
			// TODO(lrouquet): same as above
			hm.HeaderMatchSpecifier = &route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &matcher.RegexMatcher{
					EngineType: &matcher.RegexMatcher_GoogleRe2{
						GoogleRe2: &matcher.RegexMatcher_GoogleRE2{},
					},
					Regex: fmt.Sprintf(".*%s.*", regexp.QuoteMeta(xHeaderMatcher.NotContains)),
				},
			}
			hm.InvertMatch = true
		case xHeaderMatcher.Exact != "":
			hm.HeaderMatchSpecifier = &route.HeaderMatcher_ExactMatch{
				ExactMatch: xHeaderMatcher.Exact,
			}
		case xHeaderMatcher.NotExact != "":
			hm.HeaderMatchSpecifier = &route.HeaderMatcher_ExactMatch{
				ExactMatch: xHeaderMatcher.NotExact,
			}
			hm.InvertMatch = true
		}
		vhRoute.Match.Headers = append(vhRoute.Match.Headers, hm)
	}
}

func routeMatch(xRoute *Route) *route.RouteMatch {
	if xRoute.Path != "" {
		return &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Path{
				Path: xRoute.Path,
			},
		}
	}
	return &route.RouteMatch{
		PathSpecifier: &route.RouteMatch_Prefix{
			Prefix: xRoute.Match,
		},
	}
}

var responseCodeMap = map[int32]route.RedirectAction_RedirectResponseCode{
	301: route.RedirectAction_MOVED_PERMANENTLY,
	302: route.RedirectAction_FOUND,
	303: route.RedirectAction_SEE_OTHER,
	307: route.RedirectAction_TEMPORARY_REDIRECT,
	308: route.RedirectAction_PERMANENT_REDIRECT,
}

func responseCode(code int32) route.RedirectAction_RedirectResponseCode {
	if rcode, exists := responseCodeMap[code]; exists {
		return rcode
	}
	return route.RedirectAction_MOVED_PERMANENTLY
}

func routeRedirect(role EnvoyRole, ssl, tls_ingress bool, xRoute *Route) *route.Route_Redirect {
	var routeRedirect *route.Route_Redirect

	// only redirect if the Ingress is explicitely configured with TLS
	// i.e. not just if there is a SSL-enabled Listener
	if role == GatewayRole && !ssl && xRoute.HTTPSRedirect && tls_ingress {
		routeRedirect = &route.Route_Redirect{
			Redirect: &route.RedirectAction{
				SchemeRewriteSpecifier: &route.RedirectAction_HttpsRedirect{
					HttpsRedirect: true,
				},
			},
		}
	}

	if xRoute.Redirect != nil {
		if routeRedirect == nil {
			routeRedirect = &route.Route_Redirect{
				Redirect: &route.RedirectAction{},
			}
		}

		routeRedirect.Redirect.HostRedirect = xRoute.Redirect.HostRedirect
		// only one of PathRedirect or PrefixRewrite
		if xRoute.Redirect.PathRedirect != "" {
			routeRedirect.Redirect.PathRewriteSpecifier = &route.RedirectAction_PathRedirect{
				PathRedirect: xRoute.Redirect.PathRedirect,
			}
		} else if xRoute.Redirect.PrefixRewrite != "" {
			routeRedirect.Redirect.PathRewriteSpecifier = &route.RedirectAction_PrefixRewrite{
				PrefixRewrite: xRoute.Redirect.PrefixRewrite,
			}
		}
		routeRedirect.Redirect.ResponseCode = responseCode(xRoute.Redirect.ResponseCode)
		routeRedirect.Redirect.StripQuery = xRoute.Redirect.StripQuery
	}

	return routeRedirect
}

func updateClusterMeta(rc *route.RouteConfiguration, rcMeta *xds.RouteConfigurationMeta) {
	rcMeta.Clusters = set.New()

	xds.MapVHosts(rc, func(vh *route.VirtualHost) {
		xds.MapClusterNames(vh, func(clusterName string) {
			rcMeta.Clusters[clusterName] = nil
		})
	})
}

func (recv *CRDHandler) routeToVHostRoute(role EnvoyRole, ingress *Ingress,
	ssl bool, clusterFilterPort *int32, xRoute *Route) (vhRoute *route.Route) {

	if routeRedirect := routeRedirect(role, ssl, ingress.Listener.TLS != nil, xRoute); routeRedirect != nil {
		vhRoute = &route.Route{
			Match:  routeMatch(xRoute),
			Action: routeRedirect,
		}
		return
	}

	nsCRDs := recv.getNS(xRoute.namespace)

	clusterWeights := make([]*route.WeightedCluster_ClusterWeight, 0)
	var totalWeight uint32

	for _, xCluster := range xRoute.Clusters {
		var (
			kService *k8s.Service
			exists   bool
		)

		// For the GatewayRole we have Endpoints associated with Clusters
		// and can build out the full VirtualHost and all its routes such
		// that L7 processing gets requests to the correct Endpoint
		//
		// For the SidecarRole we don't have K8s giving us a list of
		// Endpoints already filtered by the Service Pod selector so we must
		// make that association ourselves by limiting what we put on the
		// VirtualHost's Routes which are paths into Cluster Endpoints
		if clusterFilterPort != nil && *clusterFilterPort != xCluster.Port {
			continue
		}

		if kService, exists = nsCRDs.services[xCluster.Name]; !exists {
			continue
		}

		for _, kServicePort := range kService.Spec.Ports {
			// match only the port declared by the Ingress's Cluster
			// the K8s Service could expose more ports
			if !xCluster.MatchServicePort(kServicePort, k8s.ProtocolTCP) {
				continue
			}

			clusterName := ClusterName(&xCluster, kService, &kServicePort)

			var clusterWeight uint32 = 1
			if xCluster.Weight != nil {
				clusterWeight = *xCluster.Weight
			}

			clusterWeights = append(clusterWeights, &route.WeightedCluster_ClusterWeight{
				Name:   clusterName,
				Weight: &wrappers.UInt32Value{Value: clusterWeight},
			})
			totalWeight += clusterWeight
		}
	}

	if xRoute.delegationFailed || (len(xRoute.Clusters) > 1 && totalWeight == 0) {
		clusterWeights = nil
	}

	// 1. We filtered on clusterFilterPort
	// 2. The Service object may not be synced
	// 3. Delegation may have failed
	// 4. The user set multiple Clusters' Weight to 0
	if len(clusterWeights) == 0 {
		switch role {
		case GatewayRole:
			// rather than create a 404, especially from https redirects, create a
			// non-existent cluster and a 503 to indicate to the service developer
			// and any clients that backends are missing, which in this case is also
			// most accurate
			clusterWeights = append(clusterWeights, &route.WeightedCluster_ClusterWeight{
				Name: constants.InvalidServiceReference,
			})
		case SidecarRole:
			return
		}
	}

	routeAction := &route.RouteAction{
		PrefixRewrite: xRoute.PrefixRewrite,
	}

	if len(clusterWeights) > 1 {
		sort.Stable(WeightedClustersByName(clusterWeights))

		routeAction.ClusterSpecifier = &route.RouteAction_WeightedClusters{
			WeightedClusters: &route.WeightedCluster{
				Clusters:    clusterWeights,
				TotalWeight: &wrappers.UInt32Value{Value: totalWeight},
			},
		}
	} else {
		routeAction.ClusterSpecifier = &route.RouteAction_Cluster{
			Cluster: clusterWeights[0].Name,
		}
	}

	if xRoute.SPDYUpgrade {
		routeAction.UpgradeConfigs = append(routeAction.UpgradeConfigs,
			&route.RouteAction_UpgradeConfig{
				UpgradeType: "spdy/3.1",
			},
		)
	}

	if xRoute.WebsocketUpgrade {
		routeAction.UpgradeConfigs = append(routeAction.UpgradeConfigs,
			&route.RouteAction_UpgradeConfig{
				UpgradeType: "websocket",
			},
		)
	}
	if len(xRoute.RateLimits) > 0 {
		xx := make([]*route.RateLimit, len(xRoute.RateLimits))
		for idx, rr := range xRoute.RateLimits {
			cp := rr.DeepCopy()
			xx[idx] = cp.RateLimit
		}
		routeAction.RateLimits = xx
	}
	if xRoute.CorsPolicy != nil {
		routeAction.Cors = &xRoute.CorsPolicy.CorsPolicy
	}
	if len(xRoute.HashPolicies) > 0 {
		hashPolicies := make([]*route.RouteAction_HashPolicy, 0, len(xRoute.HashPolicies))

		for _, hp := range xRoute.HashPolicies {
			var rahp *route.RouteAction_HashPolicy

			switch {
			case hp.Header != nil:
				rahp = &route.RouteAction_HashPolicy{
					PolicySpecifier: &route.RouteAction_HashPolicy_Header_{
						Header: &route.RouteAction_HashPolicy_Header{
							HeaderName: hp.Header.Name,
						},
					},
				}
			case hp.Cookie != nil:
				hpc := &route.RouteAction_HashPolicy_Cookie{}
				if hp.Cookie.Name != "" {
					hpc.Name = hp.Cookie.Name
				}

				if hp.Cookie.Ttl != nil {
					hpc.Ttl = ptypes.DurationProto(*hp.Cookie.Ttl)
				}

				if hp.Cookie.Path != "" {
					hpc.Path = hp.Cookie.Path
				}

				rahp = &route.RouteAction_HashPolicy{
					PolicySpecifier: &route.RouteAction_HashPolicy_Cookie_{
						Cookie: hpc,
					},
				}
			case hp.QueryParameter != nil:
				hpc := &route.RouteAction_HashPolicy_QueryParameter{
					Name: hp.QueryParameter.ParameterName,
				}
				rahp = &route.RouteAction_HashPolicy{
					PolicySpecifier: &route.RouteAction_HashPolicy_QueryParameter_{
						QueryParameter: hpc,
					},
				}
			case hp.ConnectionProperties != nil:
				rahp = &route.RouteAction_HashPolicy{
					PolicySpecifier: &route.RouteAction_HashPolicy_ConnectionProperties_{
						ConnectionProperties: &route.RouteAction_HashPolicy_ConnectionProperties{
							SourceIp: hp.ConnectionProperties.SourceIp,
						},
					},
				}
			}

			if rahp != nil {
				rahp.Terminal = hp.Terminal
				hashPolicies = append(hashPolicies, rahp)
			}
		}

		routeAction.HashPolicy = hashPolicies
	}

	if xRoute.RetryPolicy != nil {

		routeAction.RetryPolicy = &route.RetryPolicy{
			RetryOn: "5xx,connect-failure",
		}

		var retryCount uint32 = 3
		if xRoute.RetryPolicy.NumRetries > 0 {
			retryCount = xRoute.RetryPolicy.NumRetries
		}

		routeAction.RetryPolicy.NumRetries = &wrappers.UInt32Value{Value: retryCount}
		routeAction.RetryPolicy.HostSelectionRetryMaxAttempts = int64(retryCount)

		if xRoute.RetryPolicy.PerTryTimeout != "" {
			d, err := time.ParseDuration(xRoute.RetryPolicy.PerTryTimeout)
			if err == nil {
				routeAction.RetryPolicy.PerTryTimeout = ptypes.DurationProto(d)
			} else {
				recv.log.Error("time.ParseDuration", "Error", err,
					"ns", ingress.Namespace, "name", ingress.Name, "route", xRoute.Match,
					"perTryTimeout", xRoute.RetryPolicy.PerTryTimeout)
			}
		}

		// per_try_timeout docs
		// "If left unspecified, Envoy will use the global route timeout for
		// the request. Consequently, when using a 5xx based retry policy, a
		// request that times out will not be retried as the total timeout
		// budget would have been exhausted."
		//
		// For this reason we must increase the route timeout if unspecified
		// or decrease the PerTryTimeout if it is in order to get sensible
		// behavior
		if routeAction.RetryPolicy.PerTryTimeout == nil && xRoute.Timeout != 0 {

			// divide "global" route timeout by retryCount to get
			// PerTryTimeout and the intended retry behavior
			ptt := time.Duration(xRoute.Timeout / time.Duration(retryCount))
			routeAction.RetryPolicy.PerTryTimeout = ptypes.DurationProto(ptt)

		} else if routeAction.RetryPolicy.PerTryTimeout != nil && xRoute.Timeout == 0 {

			ptt, err := ptypes.Duration(routeAction.RetryPolicy.PerTryTimeout)
			if err == nil {
				// multiply PerTryTimeout by retryCount to obtain a "global"
				// route timeout and the intended retry behavior
				timeout := ptt * time.Duration(retryCount)
				routeAction.Timeout = ptypes.DurationProto(timeout)
			} else {
				recv.log.Error("ptypes.Duration", "Error", err,
					"ns", ingress.Namespace, "name", ingress.Name, "route", xRoute.Match)
			}
		}
	}

	if xRoute.Timeout < 0 {
		routeAction.Timeout = ptypes.DurationProto(0 * time.Second)
	} else if xRoute.Timeout > 0 {
		routeAction.Timeout = ptypes.DurationProto(xRoute.Timeout)
	}

	if xRoute.IdleTimeout != 0 {
		routeAction.IdleTimeout = ptypes.DurationProto(xRoute.IdleTimeout)
	}

	vhRoute = &route.Route{
		Match: routeMatch(xRoute),
		Action: &route.Route_Route{
			Route: routeAction,
		},
	}

	if role == GatewayRole {
		// IP allow/deny would break in the Sidecar
		//
		// Max header size has already been enforced
		perFilterConfig(recv.log, vhRoute, xRoute)
	}

	headerMatchers(vhRoute, xRoute)

	if add := xRoute.RequestHeadersToAdd; add != nil {
		sort.Stable(KVPByKey(xRoute.RequestHeadersToAdd))
		hvos := make([]*core.HeaderValueOption, 0, len(xRoute.RequestHeadersToAdd))
		for _, kvp := range xRoute.RequestHeadersToAdd {
			if strings.EqualFold("host", kvp.Key) {
				routeAction.HostRewriteSpecifier = &route.RouteAction_HostRewriteLiteral{
					HostRewriteLiteral: kvp.Value,
				}
			} else {
				hvos = append(hvos, &core.HeaderValueOption{
					Header: &core.HeaderValue{
						Key:   kvp.Key,
						Value: kvp.Value,
					},
					Append: &wrappers.BoolValue{
						Value: false,
					},
				})
			}
		}
		vhRoute.RequestHeadersToAdd = hvos
	}

	if remove := xRoute.RequestHeadersToRemove; remove != nil {
		sort.Strings(remove)
		vhRoute.RequestHeadersToRemove = remove
	}

	if add := xRoute.ResponseHeadersToAdd; add != nil {
		sort.Stable(KVPByKey(xRoute.ResponseHeadersToAdd))
		hvos := make([]*core.HeaderValueOption, len(xRoute.ResponseHeadersToAdd))
		for i, kvp := range xRoute.ResponseHeadersToAdd {
			hvos[i] = &core.HeaderValueOption{
				Header: &core.HeaderValue{
					Key:   kvp.Key,
					Value: kvp.Value,
				},
				Append: &wrappers.BoolValue{
					Value: false,
				},
			}
		}
		vhRoute.ResponseHeadersToAdd = hvos
	}

	if remove := xRoute.ResponseHeadersToRemove; remove != nil {
		sort.Strings(remove)
		vhRoute.ResponseHeadersToRemove = remove
	}

	return
}

func (recv *CRDHandler) ingressToVHost(sotw SotW, ingress *Ingress, ssl bool, clusterFilterPort *int32) *route.VirtualHost {
	if ssl && ingress.Listener.TLS == nil {
		return nil
	}

	vh := &route.VirtualHost{
		Name: ingress.Fqdn,
	}

	if len(ingress.VirtualHost.RateLimits) > 0 {
		rateLimits := make([]*route.RateLimit, len(ingress.VirtualHost.RateLimits))
		for i, rr := range ingress.VirtualHost.RateLimits {
			cp := rr.DeepCopy()
			rateLimits[i] = cp.RateLimit
		}
		vh.RateLimits = rateLimits
	}

	if ingress.VirtualHost.Authorization != nil {
		if vh.TypedPerFilterConfig == nil {
			vh.TypedPerFilterConfig = make(map[string]*any.Any)
		}

		eapr := ext_authz.ExtAuthzPerRoute{}
		// precisely one of Disabled or CheckSettings
		switch {
		case ingress.VirtualHost.Authorization.AuthPolicy.Disabled:
			eapr.Override = &ext_authz.ExtAuthzPerRoute_Disabled{
				Disabled: ingress.VirtualHost.Authorization.AuthPolicy.Disabled,
			}

		case len(ingress.VirtualHost.Authorization.AuthPolicy.Context) > 0:
			mp := make(map[string]string)
			for k, v := range ingress.VirtualHost.Authorization.AuthPolicy.Context {
				mp[k] = v
			}
			eapr.Override = &ext_authz.ExtAuthzPerRoute_CheckSettings{
				CheckSettings: &ext_authz.CheckSettings{
					ContextExtensions: mp,
				},
			}
		}

		vh.TypedPerFilterConfig[wellknown.HTTPExternalAuthorization] = util.ToAny(recv.log, &eapr)
	}

	if ingress.ServiceId != "" {
		if vh.TypedPerFilterConfig == nil {
			vh.TypedPerFilterConfig = make(map[string]*any.Any)
		}

		conf := header_to_metadata.Config{
			RequestRules: []*header_to_metadata.Config_Rule{
				{
					Header: constants.ServiceIdHeader,
					OnHeaderMissing: &header_to_metadata.Config_KeyValuePair{
						Key:   constants.ServiceIdHeader,
						Value: ingress.ServiceId,
					},
				},
				{
					Header: constants.ServiceIdHeader,
					OnHeaderMissing: &header_to_metadata.Config_KeyValuePair{
						Key:               constants.ServiceIdHeader,
						Value:             ingress.ServiceId,
						MetadataNamespace: wellknown.HTTPExternalAuthorization,
					},
				},
				{
					Header: constants.ServiceIdHeader,
					OnHeaderMissing: &header_to_metadata.Config_KeyValuePair{
						Key:               constants.ServiceIdHeader,
						Value:             ingress.ServiceId,
						MetadataNamespace: wellknown.HTTPGRPCAccessLog,
					},
				},
			},
		}

		vh.TypedPerFilterConfig[constants.HeaderToMetadataFilter] = util.ToAny(recv.log, &conf)
	}

	if ingress.VirtualHost.Cors != nil {
		vh.Cors = &ingress.VirtualHost.Cors.CorsPolicy
	}

	if ingress.VirtualHost.ResponseHeadersToAdd != nil {
		sort.Stable(KVPByKey(ingress.VirtualHost.ResponseHeadersToAdd))
		hvos := make([]*core.HeaderValueOption, len(ingress.VirtualHost.ResponseHeadersToAdd))
		for i, kvp := range ingress.VirtualHost.ResponseHeadersToAdd {
			hvos[i] = &core.HeaderValueOption{
				Header: &core.HeaderValue{
					Key:   kvp.Key,
					Value: kvp.Value,
				},
				Append: &wrappers.BoolValue{
					Value: false,
				},
			}
		}
		vh.ResponseHeadersToAdd = hvos
	}

	for _, xRoute := range ingress.VirtualHost.ResolvedRoutes() {
		vhRoute := recv.routeToVHostRoute(sotw.role, ingress, ssl, clusterFilterPort, xRoute)
		if vhRoute != nil {
			vh.Routes = append(vh.Routes, vhRoute)
		}
	}

	sort.Stable(RouteByLength(vh.Routes))

	switch sotw.role {
	case GatewayRole:
		vh.Domains = []string{
			ingress.Fqdn,
			ingress.Fqdn + ":*",
		}
		vh.Domains = append(vh.Domains, ingress.VirtualHost.Domains...)
		vh.RetryPolicy = &route.RetryPolicy{
			RetryOn:                       "connect-failure,reset",
			NumRetries:                    &wrappers.UInt32Value{Value: 3},
			HostSelectionRetryMaxAttempts: 3,
		}

	case SidecarRole:
		vh.Domains = []string{"*"}
		vh.RetryPolicy = &route.RetryPolicy{
			RetryOn:    "connect-failure",
			NumRetries: &wrappers.UInt32Value{Value: 3},
		}

		if perRoute := sotw.sidecar.Spec.Filters.ExtAuthzPerRoute; perRoute != nil && perRoute.CheckSettings != nil {
			vh.TypedPerFilterConfig = map[string]*any.Any{
				wellknown.HTTPExternalAuthorization: util.ToAny(recv.log, &ext_authz.ExtAuthzPerRoute{
					Override: &ext_authz.ExtAuthzPerRoute_CheckSettings{
						CheckSettings: &ext_authz.CheckSettings{
							ContextExtensions: perRoute.CheckSettings.ContextExtensions,
						},
					},
				}),
			}
		}
	}

	return vh
}

func (recv *CRDHandler) removeVirtualHost(ingress *Ingress) {

	if ingress.Fqdn == "" {
		return
	}

	sotw := recv.envoySubsets[xds.DefaultEnvoySubset]

	for _, iface := range sotw.rds {
		wrapper := iface.(xds.Wrapper)
		wrapper.Write(func(msg proto.Message, meta *interface{}) (protoChanged bool) {
			var (
				vh      *route.VirtualHost
				vhi     int
				foundVH bool
			)
			rc := msg.(*route.RouteConfiguration)
			rcMeta := (*meta).(*xds.RouteConfigurationMeta)

			for vhi, vh = range rc.VirtualHosts {
				if vh.Name == ingress.Fqdn {
					foundVH = true
					break
				}
			}

			if !foundVH {
				recv.log.Debug("did not find VirtualHost", "fqdn", ingress.Fqdn)
				return
			}
			recv.log.Warn("removed VirtualHost",
				"routeConfiguration", rc.Name, "fqdn", vh.Name,
				"ns", ingress.Namespace, "name", ingress.Name,
			)

			vhs := rc.VirtualHosts
			vhs = append(vhs[:vhi], vhs[vhi+1:]...)
			rc.VirtualHosts = vhs

			updateClusterMeta(rc, rcMeta)

			protoChanged = true
			return
		})
	}

	recv.updateSotW(xds.DefaultEnvoySubset, xds.RouteType, sotw.rds)
}

func (recv *CRDHandler) updateGatewayRDS(sotw SotW, ingresses []*Ingress) {
	var (
		shouldUpdateRDS bool
		exists          bool
		iface           interface{}
		ic              IngressClass
	)

	for _, ingress := range ingresses {

		if !ingress.Valid() || ingress.Fqdn == "" || ingress.Listener.TCPProxy != nil {
			continue
		}

		if ic, exists = recv.lc.IngressClasses[ingress.Class]; !exists {
			continue
		}

		for portName, portInfo := range ic.Ports {

			routeName := ingress.Class + portName

			var wrapper xds.Wrapper
			if iface, exists = sotw.rds[routeName]; exists {
				wrapper = iface.(xds.Wrapper)
			} else {
				wrapper = xds.NewWrapper(
					&route.RouteConfiguration{
						Name:                routeName,
						InternalOnlyHeaders: []string{constants.ServiceIdHeader},
					}, &xds.RouteConfigurationMeta{
						Clusters: set.New(),
					},
				)
				sotw.rds[routeName] = wrapper
			}

			wrapper.Write(func(msg proto.Message, meta *interface{}) (protoChanged bool) {
				var (
					vh      *route.VirtualHost
					vhi     int
					foundVH bool
				)
				rc := msg.(*route.RouteConfiguration)
				rcMeta := (*meta).(*xds.RouteConfigurationMeta)

				for vhi, vh = range rc.VirtualHosts {
					if vh.Name == ingress.Fqdn {
						foundVH = true
						break
					}
				}

				if foundVH {
					vhNew := recv.ingressToVHost(sotw, ingress, portInfo.SSL, nil)
					recv.log.Debug("foundVH", "route", routeName, "vh", vh.Name)
					if vhNew == nil {
						// We found a matching vhost in Envoy but our new config for it is null
						// the vhost needs to be removed from the route_config
						// (example: TLS was removed from the Ingress)
						rc.VirtualHosts = append(rc.VirtualHosts[:vhi], rc.VirtualHosts[vhi+1:]...)
						recv.log.Warn("removed VH from RouteConfiguration",
							"route", routeName, "fqdn", ingress.Fqdn,
							"ns", ingress.Namespace, "name", ingress.Name,
						)
						protoChanged = true
						recv.log.Debug("protoChanged", "route", routeName, "vh", vh.Name)
					} else {
						if !proto.Equal(vh, vhNew) {
							rc.VirtualHosts[vhi] = vhNew
							protoChanged = true
							recv.log.Debug("protoChanged", "route", routeName, "vh", vhNew.Name)
						}
					}
				} else {
					vh = recv.ingressToVHost(sotw, ingress, portInfo.SSL, nil)
					if vh != nil {
						rc.VirtualHosts = append(rc.VirtualHosts, vh)
						sort.Stable(VhostByName(rc.VirtualHosts))
						protoChanged = true
						recv.log.Debug("protoChanged", "route", routeName, "vh", vh.Name)
					}
				}

				if protoChanged {
					updateClusterMeta(rc, rcMeta)
					shouldUpdateRDS = true
				}

				return
			})
		}
	}

	if shouldUpdateRDS {
		recv.updateSotW(xds.DefaultEnvoySubset, xds.RouteType, sotw.rds)
	}
}

func (recv *CRDHandler) updateSidecarRDS(sotw SotW, ingress *Ingress) {
	var (
		shouldUpdateRDS bool
		kService        *k8s.Service
		wrapper         xds.Wrapper
		exists          bool
		iface           interface{}
	)

	if !ingress.Valid() || ingress.Listener.TCPProxy != nil {
		return
	}

	nsCRDs := recv.getNS(ingress.Namespace)
	uniqueRouteConfigs := set.New()

	for _, xRoute := range ingress.VirtualHost.ResolvedRoutes() {
		for _, cluster := range xRoute.Clusters {
			if kService, exists = nsCRDs.services[cluster.Name]; !exists {
				continue
			}

			for _, kServicePort := range kService.Spec.Ports {
				// match only the port declared by the Ingress's Cluster
				// the K8s Service could expose more ports
				if !cluster.MatchServicePort(kServicePort, k8s.ProtocolTCP) {
					continue
				}

				routeConfigName := ClusterName(&cluster, kService, &kServicePort, OptNoHash)

				// Routes can contain duplicative Cluster/Port combinations
				//
				// We only need one RouteConfig for each unique combination
				if _, exists = uniqueRouteConfigs[routeConfigName]; exists {
					continue
				}

				newRouteConfig := &route.RouteConfiguration{
					Name: routeConfigName,
					VirtualHosts: []*route.VirtualHost{
						recv.ingressToVHost(sotw, ingress, false, &cluster.Port),
					},
				}

				if iface, exists = sotw.rds[routeConfigName]; exists {
					wrapper = iface.(xds.Wrapper)
					if wrapper.CompareAndReplace(recv.log, newRouteConfig) {
						shouldUpdateRDS = true
					}
				} else {
					wrapper = xds.NewWrapper(
						newRouteConfig,
						&xds.RouteConfigurationMeta{
							Clusters: set.New(),
						},
					)
					shouldUpdateRDS = true
				}

				if shouldUpdateRDS {
					wrapper.Write(func(msg proto.Message, meta *interface{}) (protoChanged bool) {
						rc := msg.(*route.RouteConfiguration)
						rcMeta := (*meta).(*xds.RouteConfigurationMeta)

						updateClusterMeta(rc, rcMeta)
						return
					})
				}

				uniqueRouteConfigs[routeConfigName] = wrapper
			}
		}
	}

	// sotw.rds isn't assignable since SotW is stored as a value
	for k := range sotw.rds {
		if _, exists := uniqueRouteConfigs[k]; !exists {
			delete(sotw.rds, k)
		}
	}
	for k := range uniqueRouteConfigs {
		sotw.rds[k] = uniqueRouteConfigs[k]
	}

	if shouldUpdateRDS {
		recv.updateSotW(sotw.subset, xds.RouteType, sotw.rds)
	}
}

func (recv *CRDHandler) updateRDS(iface, ifaceOld interface{}) {
	var (
		ingresses           []*Ingress
		ingress, ingressOld *Ingress
	)

	switch crd := iface.(type) {

	case *Ingress:
		ingress = crd
		if ifaceOld != nil {
			ingressOld = ifaceOld.(*Ingress)
		}

		ingresses = []*Ingress{ingress}

	case *k8s.Service:
		ingresses = recv.getIngressList(crd.Namespace, crd.Name)

	default:
		recv.log.Error("updateRDS received unknown type",
			"TypeOf", reflect.TypeOf(iface).String())
		return
	}

	if ingress != nil && !recv.commonUpdateLogic(ingress, ingressOld, recv.removeVirtualHost) {
		return
	}

	for _, ingress := range ingresses {
		for _, sotw := range recv.getSotWs(ingress) {
			switch sotw.role {
			case GatewayRole:
				recv.updateGatewayRDS(sotw, ingresses)
			case SidecarRole:
				recv.updateSidecarRDS(sotw, ingress)
			}
		}
	}
}
