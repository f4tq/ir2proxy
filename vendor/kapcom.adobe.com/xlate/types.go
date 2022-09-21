package xlate

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"kapcom.adobe.com/ciphers"
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/envoy_api"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/encoding/protojson"
	k8s "k8s.io/api/core/v1"
)

const IngressTypeURL = "kapcom.adobe.io/v1/Ingress"

type (
	// +k8s:deepcopy-gen=true
	Ingress struct {
		Name      string
		Namespace string

		// ResourceVersion is required when doing a status update on IngressRoute
		// but not Ingress! This could be a bug in CRD v1beta1
		// Only used by IngressRoute
		// TODO(lrouquet): see if this can be removed when moving to CRD v1
		ResourceVersion string

		// Concrete type to distinguish between different CRDs that could live
		// in the same Namespace and have the same Name
		TypeURL string

		// CRD migration (default: Ingress 0, IngressRoute 1, HTTPProxy 2)
		Priority int

		// Ingress Class. Don't stutter
		Class string

		// value of x-service-id
		ServiceId string

		ValidationError string

		// During CRD translation into this struct there may be errors which
		// need to be reported. Since the original CRD is gone we need to
		// preserve the error
		CRDError string

		// Status of the resource, read from k8s
		LastCRDStatus string
		// TODO(lrouquet): implement LoadBalancerStatus
		// LastLBStatus  []struct {
		// 	Hostname string
		// 	IP       string
		// }

		Fqdn string

		Listener Listener

		VirtualHost VirtualHost
	}

	// +k8s:deepcopy-gen=true
	Listener struct {
		TLS      *TLS
		TCPProxy *TCPProxy

		delegateTCPProxy *TCPProxy
	}

	AuthorizationPolicy struct {
		Disabled bool
		Context  map[string]string
	}

	AuthorizationServer struct {
		//
		// ExtensionServiceRef -- for now, this points to the statically configure Authz service
		AuthPolicy *AuthorizationPolicy
		// ResponseTimeout configures maximum time to wait for a check response from the authorization server.
		ResponseTimeout time.Duration
		// If FailOpen is true, the client request is forwarded to the upstream service
		FailOpen bool
	}

	GRPCLogger struct {
		Host string `json:"host,omitempty"`
		Port uint16 `json:"port,omitempty"`
	}
	// +k8s:deepcopy-gen=true
	Logger struct {
		GRPC *GRPCLogger `json:"grpc,omitempty"`
	}
	// +k8s:deepcopy-gen=true
	Logging struct {
		Loggers []Logger `json:"loggers,omitempty"`
	}

	VirtualHost struct {
		// use this carefully. delegation must always be considered
		Routes []*Route

		// Route pointer to nil
		// TODO(bcook) this causes deepcopy-gen to fail
		delegateRoutes map[*Route]interface{}

		Cors    *CorsPolicy
		Domains []string

		// AuthorizationServer - authorization for this virtual host. Authorization can
		// only be configured on virtual hosts that have TLS enabled.
		Authorization *AuthorizationServer

		RateLimits []*RateLimit

		// vhost-level response-headers-to-add, currently not exposed in the CRD
		ResponseHeadersToAdd []KVP

		Logging Logging
	}

	// +k8s:deepcopy-gen=true
	TLS struct {
		SecretName         string
		MinProtocolVersion tls.TlsParameters_TlsProtocol
		MaxProtocolVersion tls.TlsParameters_TlsProtocol
		CipherSuites       []string
		Passthrough        bool
	}

	// +k8s:deepcopy-gen=true
	TCPProxy struct {
		Delegate         *Delegate
		namespace        string // copy of the namespace to which this TCPProxy belongs
		delegationFailed bool

		Clusters []Cluster
	}

	// +k8s:deepcopy-gen=true
	Route struct {
		Delegate                *Delegate
		namespace               string // copy of the namespace to which this Route belongs
		delegationFailed        bool
		CorsPolicy              *CorsPolicy
		Match                   string // Prefix match
		Path                    string // Exact match
		HeaderMatchers          []HeaderMatcher
		PrefixRewrite           string
		SPDYUpgrade             bool
		WebsocketUpgrade        bool
		HTTPSRedirect           bool
		RetryPolicy             *RetryPolicy
		Timeout                 time.Duration // "0" means unset; "< 0" means "no timeout" (e.g. infinity)
		IdleTimeout             time.Duration
		HashPolicies            []HashPolicy
		PerFilterConfig         *PerFilterConfig
		RequestHeadersToAdd     []KVP
		RequestHeadersToRemove  []string
		ResponseHeadersToAdd    []KVP
		ResponseHeadersToRemove []string
		RateLimits              []*RateLimit

		Clusters []Cluster

		Redirect *Redirect
	}

	// +k8s:deepcopy-gen=true
	HeaderMatcher struct {
		Name        string `json:"name"`
		Present     *bool  `json:"present,omitempty"`
		Contains    string `json:"contains,omitempty"`
		NotContains string `json:"notcontains,omitempty"`
		Exact       string `json:"exact,omitempty"`
		NotExact    string `json:"notexact,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	RetryPolicy struct {
		NumRetries    uint32
		PerTryTimeout string
	}

	ExtAuthzPerRoute struct {
		ext_authz.ExtAuthzPerRoute
	}

	CorsPolicy = envoy_api.CorsPolicy

	// +k8s:deepcopy-gen=true
	PerFilterConfig struct {
		IpAllowDeny *IpAllowDeny      `json:"envoy.filters.http.ip_allow_deny,omitempty"`
		HeaderSize  *HeaderSize       `json:"envoy.filters.http.header_size,omitempty"`
		Authz       *ExtAuthzPerRoute `json:"envoy.filters.http.ext_authz,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	IpAllowDeny struct {
		AllowCidrs []Cidr `json:"allow_cidrs,omitempty"`
		DenyCidrs  []Cidr `json:"deny_cidrs,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	Cidr struct {
		AddressPrefix string `json:"address_prefix,omitempty"`
		// This is Envoy's internal storage type as well
		PrefixLen uint32 `json:"prefix_len,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	Redirect struct {
		HostRedirect  string `json:"host,omitempty"`
		PathRedirect  string `json:"path,omitempty"`
		PrefixRewrite string `json:"prefix,omitempty"`
		ResponseCode  int32  `json:"responseCode,omitempty"`
		StripQuery    bool   `json:"stripQuery,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	HeaderSize struct {
		HeaderSize HeaderSizeSetting `json:"header_size,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	HeaderSizeSetting struct {
		MaxBytes *int `json:"max_bytes,omitempty"`
	}

	// +k8s:deepcopy-gen=true
	HashPolicy struct {
		Header *HashPolicyHeader

		Cookie *HashPolicyCookie

		ConnectionProperties *HashPolicyConnectionProperties

		Terminal bool
	}

	// +k8s:deepcopy-gen=true
	HashPolicyHeader struct {
		Name string
	}

	// +k8s:deepcopy-gen=true
	HashPolicyCookie struct {
		Name string
		Ttl  *time.Duration
		Path string
	}

	// +k8s:deepcopy-gen=true
	HashPolicyConnectionProperties struct {
		SourceIp bool
	}

	// +k8s:deepcopy-gen=true
	KVP struct {
		Key   string
		Value string
	}

	// +k8s:deepcopy-gen=true
	EndpointCircuitBreaker struct {
		MaxConnections     uint32
		MaxPendingRequests uint32
		MaxRequests        uint32
	}

	// +k8s:deepcopy-gen=true
	Cluster struct { // no maps on this or encoding/gob will become nondeterministic
		Name                 string
		Port                 int32
		PortName             string
		Weight               *uint32
		LbPolicy             cluster.Cluster_LbPolicy
		LeastRequestLbConfig *LeastRequestLbConfig
		IdleTimeout          time.Duration
		HealthCheck          *HealthCheck
		ConnectTimeout       time.Duration

		// these settings are adjusted dynamically based on endpoint count
		EndpointCircuitBreaker *EndpointCircuitBreaker
	}

	// +k8s:deepcopy-gen=true
	LeastRequestLbConfig struct {
		ChoiceCount uint32
	}

	// +k8s:deepcopy-gen=true
	HealthCheck struct {
		Path               string
		Host               string
		Timeout            time.Duration
		Interval           time.Duration
		UnhealthyThreshold uint32
		HealthyThreshold   uint32
	}

	// +k8s:deepcopy-gen=true
	Delegate struct {
		Name      string
		Namespace string
	}

	IngressStatus interface {
		// Type() returns a unique type for this Ingress
		Type() string
		// StatusChanged returns whether the given Ingress status has changed; if so,
		// a string description of the new status is returned as well
		StatusChanged(*Ingress) (bool, string)
		// PrepareForStatusUpdate() converts the given Ingress to its CRD native equivalent
		// that can be used with UpdateStatus(crd)
		PrepareForStatusUpdate(*Ingress) interface{}
	}
)

type RoutesLongestFirst []*Route

func (recv RoutesLongestFirst) Len() int {
	return len(recv)
}
func (recv RoutesLongestFirst) Less(i, j int) bool {
	// same length matches need to sort consistently
	if len(recv[i].Match) == len(recv[j].Match) {
		return recv[i].Match < recv[j].Match
	}
	return len(recv[i].Match) > len(recv[j].Match) // longest first
}
func (recv RoutesLongestFirst) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

type KVPByKey []KVP

func (recv KVPByKey) Len() int {
	return len(recv)
}
func (recv KVPByKey) Less(i, j int) bool {
	return recv[i].Key < recv[j].Key
}
func (recv KVPByKey) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VirtualHost) DeepCopyInto(out *VirtualHost) {
	*out = *in
	if in.Routes != nil {
		in, out := &in.Routes, &out.Routes
		*out = make([]*Route, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(Route)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.Domains != nil {
		in, out := &in.Domains, &out.Domains
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VirtualHost.
func (in *VirtualHost) DeepCopy() *VirtualHost {
	if in == nil {
		return nil
	}
	out := new(VirtualHost)
	in.DeepCopyInto(out)
	return out
}

func (recv *VirtualHost) ResolvedRoutes() (routes []*Route) {
	for _, route := range recv.Routes {
		// delegated Routes that fail should still be represented in RDS to
		// more accurately produce a 503 NR
		if route.Delegate == nil || route.delegationFailed {
			routes = append(routes, route)
		}
	}
	for route := range recv.delegateRoutes {
		routes = append(routes, route)
	}
	return
}

func (recv *VirtualHost) AddResponseHeader(key, val string) {
	var found bool
	for i := range recv.ResponseHeadersToAdd {
		if recv.ResponseHeadersToAdd[i].Key == key {
			recv.ResponseHeadersToAdd[i].Value = val
			found = true
		}
	}
	if !found {
		recv.ResponseHeadersToAdd = append(recv.ResponseHeadersToAdd, KVP{Key: key, Value: val})
	}
}

func (recv *VirtualHost) RemoveResponseHeader(key string) {
	var (
		found bool
		i     int
	)
	for i = range recv.ResponseHeadersToAdd {
		if recv.ResponseHeadersToAdd[i].Key == key {
			found = true
			break
		}
	}
	if found {
		recv.ResponseHeadersToAdd = append(recv.ResponseHeadersToAdd[:i], recv.ResponseHeadersToAdd[i+1:]...)
	}
}

func (recv *EndpointCircuitBreaker) maxConnections(endpoints uint32) *wrappers.UInt32Value {
	if recv == nil || recv.MaxConnections == 0 || endpoints == 0 {
		return &wrappers.UInt32Value{Value: 1000000}
	}
	return &wrappers.UInt32Value{
		Value: recv.MaxConnections * endpoints,
	}
}

func (recv *EndpointCircuitBreaker) maxPendingRequests(endpoints uint32) *wrappers.UInt32Value {
	if recv == nil || recv.MaxPendingRequests == 0 || endpoints == 0 {
		return nil // use Envoy default
	}
	return &wrappers.UInt32Value{
		Value: recv.MaxPendingRequests * endpoints,
	}
}

func (recv *EndpointCircuitBreaker) maxRequests(endpoints uint32) *wrappers.UInt32Value {
	if recv == nil || recv.MaxRequests == 0 || endpoints == 0 {
		return &wrappers.UInt32Value{Value: 1000000}
	}
	return &wrappers.UInt32Value{
		Value: recv.MaxRequests * endpoints,
	}
}

func (recv *ExtAuthzPerRoute) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(&recv.ExtAuthzPerRoute)
}

func (recv *ExtAuthzPerRoute) UnmarshalJSON(bs []byte) error {
	return protojson.Unmarshal(bs, &recv.ExtAuthzPerRoute)
}

func (recv *ExtAuthzPerRoute) DeepCopy() *ExtAuthzPerRoute {
	eapr := new(ExtAuthzPerRoute)
	eapr.DeepCopyInto(recv)
	return eapr
}

func (in *ExtAuthzPerRoute) DeepCopyInto(out *ExtAuthzPerRoute) {
	bs, _ := in.MarshalJSON()
	json.Unmarshal(bs, out)
}

func (recv *Cluster) MatchServicePort(port k8s.ServicePort, protocol k8s.Protocol) bool {
	if port.Protocol != protocol {
		return false
	}
	// one of Cluster.Port or Cluster.PortName will be set
	// a K8s Service port number is always set (Name is optional if the Service only has 1 port)
	return port.Port == recv.Port || (recv.PortName != "" && port.Name == recv.PortName)
}

func (recv *Listener) ResolvedTCPProxy() (tcpProxy *TCPProxy) {
	if recv.TCPProxy == nil {
		return
	}
	// delegated TCPProxy that fail should still be represented in xDS to
	// more accurately produce an error
	if recv.TCPProxy.Delegate == nil || recv.TCPProxy.delegationFailed {
		tcpProxy = recv.TCPProxy
	} else {
		tcpProxy = recv.delegateTCPProxy
	}
	return
}

func (recv *Ingress) SetValid() {
	recv.ValidationError = ""
}

func (recv *Ingress) SetInvalid(reason string) {
	recv.ValidationError = reason
}

func (recv *Ingress) Valid() bool {
	return recv.ValidationError == "" && recv.CRDError == ""
}

// Ingress structural validation outside of specific CRDErrors that are
// difficult to communicate back to the user, and validations that can only
// happen across Ingresses such as FQDN collisions
func (recv *Ingress) Validate() {
	if !recv.Valid() {
		return
	}

	if recv.Class == "" {
		recv.SetInvalid("Missing ingress class")
		return
	}

	if recv.Listener.TCPProxy == nil {
		switch {
		case len(recv.VirtualHost.Routes) == 0:
			recv.SetInvalid("VirtualHost has no Routes")
			return
		case recv.VirtualHost.Authorization != nil && !AuthzEnabled():
			recv.SetInvalid("Virtualhost requires authorization but authz not enabled")
			return
		case recv.VirtualHost.Authorization != nil && recv.Listener.TLS == nil:
			recv.SetInvalid("Virtualhost requires authorization which requires TLS to be enabled")
			return
		}
		for _, route := range recv.VirtualHost.Routes {
			if route.Match == "" && route.Path == "" {
				recv.SetInvalid("Route has no Match or Path")
				return
			}

			if len(route.Clusters) == 0 && route.Delegate == nil && route.Redirect == nil {
				recv.SetInvalid("Route has no Clusters or Delegate or Redirect")
				return
			}

			if route.Redirect != nil {
				if route.Redirect.PathRedirect != "" && route.Redirect.PrefixRewrite != "" {
					recv.SetInvalid("Redirect: only one of Path, Prefix may be specified")
					return
				}
			}
			if route.PerFilterConfig != nil && route.PerFilterConfig.Authz != nil {
				switch {
				case recv.Listener.TLS == nil:
					recv.SetInvalid("cannot enable route authz on non tls listener")
					return
				case recv.VirtualHost.Authorization == nil:
					recv.SetInvalid("route configures authz but virtualhost does not")
					return
				}
			}
		}
	} else {
		if len(recv.Listener.TCPProxy.Clusters) == 0 && recv.Listener.TCPProxy.Delegate == nil {
			recv.SetInvalid("TCPProxy has no Clusters and does not delegate")
			return
		}
	}

	// Individual properties validation
	// needs to be done only when an Ingress is added/updated (TODO:lrouquet)
	if recv.Listener.TLS != nil {
		// validate custom CipherSuites
		var invalidCiphers []string
		for _, cs := range recv.Listener.TLS.CipherSuites {
			cs = strings.TrimPrefix(cs, "[")
			cs = strings.TrimSuffix(cs, "]")
			for _, c := range strings.Split(cs, "|") {
				if !ciphers.IsCurated(c) {
					invalidCiphers = append(invalidCiphers, c)
				}
			}
		}
		if len(invalidCiphers) > 0 {
			msg := fmt.Sprintf("Invalid or unsupported cipher(s): %s", strings.Join(invalidCiphers, ", "))
			recv.SetInvalid(msg)
		}
	}
}

// mapClusters maps the specified function onto each Cluster
// in the Ingress and returns true if mapping should stop
func (recv *Ingress) mapClusters(mapFunc func(Cluster, string) bool) {
	if recv == nil {
		return
	}
	if tcpProxy := recv.Listener.ResolvedTCPProxy(); tcpProxy != nil {
		for _, cluster := range tcpProxy.Clusters {
			if mapFunc(cluster, tcpProxy.namespace) {
				return
			}
		}
	} else {
		for _, route := range recv.VirtualHost.ResolvedRoutes() {
			for _, cluster := range route.Clusters {
				if mapFunc(cluster, route.namespace) {
					return
				}
			}
		}
	}
}

// IsClusterService -- gw authz and ratelimit are special services whose clusters are read from templates not constructed by kapcom
func (recv *Ingress) IsClusterService() bool {
	return recv.Class == constants.AuthzClass || recv.Class == constants.RatelimitClass
}

// Analogous returns whether the given ingress represents
// the same Ingress during CRD migration:
//   i.e. same name, same namespace, same fqdn but different type
func (recv *Ingress) Analogous(ingress *Ingress) (akin bool) {
	if !config.EnableCRDMigration() {
		return
	}

	// a null ingress is not analogous
	if ingress == nil {
		return
	}

	if ingress.Name == recv.Name &&
		ingress.Namespace == recv.Namespace &&
		ingress.Fqdn == recv.Fqdn &&
		ingress.TypeURL != recv.TypeURL {
		akin = true
	}
	return
}
