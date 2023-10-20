package xlate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/envoy_api"
	"kapcom.adobe.com/xds"

	"github.com/davecgh/go-spew/spew"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authz_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	authzFlags = &AuthzFlags{}
	// See envoy/examples/ext_authz/config/http-service
	authzconverter = &extAuth2Converter{TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"}
)

func AuthzEnabled() bool {
	return authzFlags.Enabled.Value()
}
func AuthzInternalMTLS() bool {
	config.Log.Debug(fmt.Sprintf("AuthzInternalMTLS authzFlags.Mtls == config.Internal %t", authzFlags.Mtls == config.Internal))
	return authzFlags.Mtls == config.Internal
}
func init() {
	// register the config struct
	config.AddConfiguration(&config.CommandLineOptionsGroup{
		ShortDescription: "Authz flags",
		LongDescription:  "Authz Flags",
		Namespace:        "authz",
		EnvNamespace:     "AUTHZ",
		Options:          authzFlags})

	// register the converter with envoy_api
	envoy_api.RegisterFilterConverter(authzconverter)
}

type (
	ExtAuthz = envoy_api.HttpExtAuthz

	// AuthzFlags -- toplevel ratelimit flags.  There are common flags and grpc ServiceConfig flags for envoy or google backend services
	//
	AuthzFlags struct {
		Enabled config.Truthy         `long:"enable" env:"ENABLE" description:"Enable Authz"`
		Mtls    config.CertManagement `long:"mtls" env:"MTLS" default:"none" description:"mtls cert managemment.  accepted values: none,(internal|kapcom),external"`

		FilterFromFile  string `long:"filter-file" env:"FILTER_FILE" description:"Read the entire authz filter config from file" `
		ClusterFromFile string `long:"cluster-file" env:"CLUSTER_FILE" description:"Read the entire authz static cluster config from file" `
		// private extauthz hcm filter instantiations taken from FILE_FILTER
		filter *envoy_api.HttpExtAuthz
		// private cluster instantiations taken from CLUSTER_FILTER
		cluster *cluster.Cluster
	}
	// struct to provide envoy filter json conversion
	extAuth2Converter struct {
		TypeUrl string
	}
)

func (flags *AuthzFlags) Reset() {
	*flags = AuthzFlags{}
}
func AuthzService() *envoy_api.HttpExtAuthz {
	return authzFlags.filter
}
func AuthzFilter() *envoy_api.HttpExtAuthz {
	if authzFlags.filter != nil {
		config.Log.Debug(fmt.Sprintf("AuthzFilter %s\n", spew.Sprint(authzFlags.filter)))
		// we read the filter from a file so no need to build it from flags
		// Validate applies any env/cli overrides
		return authzFlags.filter
	}
	return nil
}
func AuthzCluster() *cluster.Cluster {
	if authzFlags.cluster != nil {
		config.Log.Debug(fmt.Sprintf("AuthzCluster %s\n", spew.Sprint(authzFlags.filter)))
		// we read the filter from a file so no need to build it from flags
		// Validate applies any env/cli overrides
		return authzFlags.cluster
	}
	return nil
}

// RatelimitClusterName -- return the Ratelimit cluster name
func AuthzClusterName() string {
	if authzFlags.cluster != nil {
		return authzFlags.cluster.GetName()
	}
	return ""
}

// Validate -- top-level validation of authz flags.  Implementation of Config interface
func (flags *AuthzFlags) Validate(cfg *config.KapcomConfig) error {
	config.Log.Debug("authz.Flags validate")
	if !flags.Enabled.Value() {
		return nil
	}
	config.Log.Debug(fmt.Sprintf("Authz.Validatation flags %s\n", spew.Sprint(flags)))
	if len(flags.FilterFromFile) == 0 {
		return errors.New("authz filter definiton file must be provided ")
	}
	bb, err := ioutil.ReadFile(flags.FilterFromFile)
	if err != nil {
		return fmt.Errorf("authz filter from file error %s", err.Error())
	}
	//rr := &authz_http.ExtAuthz{}
	rr := &envoy_api.HttpExtAuthz{}
	err = rr.UnmarshalJSON(bb)
	if err != nil {
		return fmt.Errorf("authz filter from file error %s", err.Error())
	}
	config.Log.Debug(fmt.Sprintf("Authz.Validate file %s read %s\n", flags.FilterFromFile, spew.Sprint(rr)))
	switch {
	case rr.Services == nil:
		config.Log.Error("Either grpc or http service must be defined")
		return errors.New("authz requires either grpc or http service definition")
	case rr.GetGrpcService() != nil:
		config.Log.Info("Authz grpc service defined")
		svc := rr.GetGrpcService()
		if svc.Timeout != nil {
			config.Log.Info(fmt.Sprintf("Authz grpc service timeout %f seconds", svc.GetTimeout().AsDuration().Seconds()))
		}
		switch {
		case rr.GetGrpcService().GetEnvoyGrpc() != nil:
			envoy_grpc := rr.GetGrpcService().GetEnvoyGrpc()
			if len(envoy_grpc.GetClusterName()) == 0 {
				return errors.New("envoy grpc requires a ClusterName for envoy grpc")
			}
		case rr.GetGrpcService().GetGoogleGrpc() != nil:
			google_grpc := rr.GetGrpcService().GetGoogleGrpc()
			if len(google_grpc.TargetUri) == 0 {
				return errors.New("targetURI must defined for envoy grpc")
			}
			config.Log.Info("authz googlegrpc service defined")
		default:
			return fmt.Errorf("unknown grpc service type used %T provided", rr.GetGrpcService().TargetSpecifier)
		}
	case rr.GetHttpService() != nil:
		httpSvc := rr.GetHttpService()
		if httpSvc.ServerUri == nil {
			//tmp:= authz_cfg.HttpService{ ServerUri: &envoy_api_v2_core.HttpUri{}}
			httpSvc.ServerUri = &envoy_config_core_v3.HttpUri{} //&envoy_api_v2_core.HttpUri{}
			bb, err := protojson.MarshalOptions{Multiline: true, AllowPartial: true, EmitUnpopulated: true}.Marshal(httpSvc)
			if err != nil {
				return fmt.Errorf("authz http service initialization error %s", err.Error())
			}
			return fmt.Errorf("authz http service cannot have nil values in %s", string(bb))
		}

		if len(httpSvc.ServerUri.Uri) == 0 {
			return errors.New("authz http service requires prefix")
		}
		if len(httpSvc.PathPrefix) == 0 {
			httpSvc.PathPrefix = "/"
			//			return errors.New("authz http service requires path prefix")
		}
		if httpSvc.GetAuthorizationRequest() == nil {
			config.Log.Warn("authz http service has no authorization request")
		}
		if httpSvc.GetAuthorizationResponse() == nil {
			config.Log.Warn("authz http service has no authorization response")
		}
		if len(flags.ClusterFromFile) == 0 {
			return errors.New("must define cluster for authz http service")
		}

	default:
		return fmt.Errorf("authz validate - unknown grpc kind %T", rr.Services)
	}
	// inhale the cluster config
	cluster := &cluster.Cluster{}
	bb, err = ioutil.ReadFile(flags.ClusterFromFile)
	if err != nil {
		return fmt.Errorf("authz cluster from file error %s", err.Error())
	}
	err = protojson.Unmarshal(bb, cluster)
	if err != nil {
		config.Log.Debug(spew.Sdump(cluster))
		return fmt.Errorf("authz cluster  from file error %s", err.Error())
	}
	switch {
	case len(cluster.GetName()) == 0:
		return errors.New("clustername required for authz cluster")
	case len(cluster.LoadAssignment.GetClusterName()) == 0:
		return errors.New("clustername required for authz cluster")
	}
	// check mtls
	switch authzFlags.Mtls {
	case config.Internal:
		if cluster.GetTransportSocket() != nil {
			return fmt.Errorf("authz mtls specifies kapcom managed certs but provides external transport socket")
		}
	case config.External:
		switch {
		case cluster.GetTransportSocket() == nil:
			return fmt.Errorf("authz cluster wants external cert management but does not provide tls context")
		case cluster.GetTransportSocket().Name != "envoy.transport_sockets.tls":
			return fmt.Errorf("authz cluster wants external cert management but does not provide tls context")
		}
		// case None - effectively: don't interfere
	}

	flags.cluster = cluster

	flags.filter = rr
	return nil
}

func (recv *extAuth2Converter) Type() string {
	return recv.TypeUrl
}

// String -- same a type but useful in string contexts
func (recv *extAuth2Converter) String() string { return recv.Type() }

// Unmarshal -- read a protojson rep of proto authz.ExtAuthz
func (recv *extAuth2Converter) Unmarshal(bb []byte) (interface{}, error) {
	xx := envoy_api.NewAuthz()
	err := xx.UnmarshalJSON(bb)
	if err != nil {
		return nil, err
	}
	return &xx, nil
}

// Alias proto ratelimit_http Ratelimit so the Marshal will insert envoy @type
//   - don not confuse with route_v3.Ratelimit.
type AuthzAlias authz_http.ExtAuthz

// MarshalJSON -- uses protojson to marshall correctly
func (recv *AuthzAlias) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*authz_http.ExtAuthz)(recv))
}

// Marshal @type type.googleapis.com/envoy.extensions.filters."
func (recv *extAuth2Converter) Marshal(data interface{}) ([]byte, error) {
	ty, ok := data.(*authz_http.ExtAuthz)
	if !ok {
		return nil, errors.New("marshal failed: not *authz.ExtAuthz")
	}
	xx := struct {
		Type string `json:"@type,omitempty"`
		*AuthzAlias
	}{
		Type:       recv.Type(),
		AuthzAlias: (*AuthzAlias)(ty),
	}
	return json.Marshal(&xx)
}
func (recv *extAuth2Converter) Compare(a interface{}, b interface{}) error {
	A, ok := a.(*authz_http.ExtAuthz)
	if !ok {
		return errors.New("Compare failed: not *authz.ExtAuthz")
	}
	B, ok := a.(*authz_http.ExtAuthz)
	if !ok {
		return errors.New("failed: not *authz.ExtAuthz")
	}
	ax, err := protojson.Marshal(A)
	if err != nil {
		return fmt.Errorf("failed serializing A %s", err.Error())
	}
	bx, err := protojson.Marshal(B)
	if err != nil {
		return fmt.Errorf("Compared failed serializing B %s", err.Error())
	}
	if string(ax) != string(bx) {
		return fmt.Errorf("Compare failed:  >%s< != >%s<", string(ax), string(bx))
	}
	return nil
}

// AuthzHcmFilterDefault -- convert the flags settings into the protobuf atelimit_v3.RateLimit struct needed by envoy
func AuthzHcmFilterDefault() *envoy_api.HttpExtAuthz {
	if AuthzEnabled() && authzFlags.filter != nil {
		config.Log.Info(spew.Sprintf("AuthzHcmFilter requested %s", authzFlags.filter))
		return authzFlags.filter
	}
	return nil
}

func AuthzHcmFilter(ingress *Ingress) *envoy_api.HttpExtAuthz {
	if ingress == nil {
		config.Log.Error("AuthzHcmFilter", "Error", "no ingress")
		return nil
	}
	tmplt := AuthzHcmFilterDefault()
	if tmplt == nil {
		config.Log.Error("AuthzHcmFilter", "Error", "No extAuthz default set")
		return nil
	}
	bs, err := protojson.Marshal(tmplt)
	if err != nil {
		config.Log.Error("AuthzHcmFilter marshal", "Error", err)
		return nil
	}
	cp := &envoy_api.HttpExtAuthz{}
	err = cp.UnmarshalJSON(bs)
	if err != nil {
		config.Log.Error("AuthzHcmFilter copy", "Error", err)
		return nil
	}
	// Ingress-defined FailOpen/Timeout configuration
	cp.FailureModeAllow = ingress.VirtualHost.Authorization.FailOpen
	responseTimeout := ingress.VirtualHost.Authorization.ResponseTimeout
	if responseTimeout != 0 {
		switch {
		case cp.GetGrpcService() != nil:
			if svc := cp.GetGrpcService(); svc != nil {
				svc.Timeout = ptypes.DurationProto(responseTimeout)
			}
		case cp.GetHttpService() != nil:
			if svc := cp.GetHttpService(); svc != nil {
				svc.ServerUri.Timeout = ptypes.DurationProto(responseTimeout)
			}
		}
	}

	return cp
}

// initAuthzCluster -- implementation of the authz envoy cluster taken from file --authz-cluster-file
//
//	which transforms into a static envoy cluster
func initAuthzCluster() (xds.Wrapper, error) {
	if authzFlags.cluster != nil {
		return xds.NewWrapper(authzFlags.cluster), nil
	}
	return nil, errors.New("no authz cluster exists.  is this a google grpc implementation?")
}

// interface to CRDHandler
func (recv *CRDHandler) initAuthzCluster() {
	wrap, err := initAuthzCluster()
	if err != nil {
		recv.log.Error(fmt.Sprintf("authz init error %s", err.Error()))
		return
	}
	recv.authzCluster = wrap
}

// RequiresAuthzFilter -- helper function
func RequiresAuthzFilter(ingress *Ingress) bool {
	if ingress.VirtualHost.Authorization != nil {
		return true
	}
	for _, r := range ingress.VirtualHost.ResolvedRoutes() {
		if r.PerFilterConfig != nil && r.PerFilterConfig.Authz != nil {
			return true
		}
	}
	return false
}

// Ensure auth is configured on the delegator when a delegate requires it
// this func can invalidate both the delegate and its parent
func (recv *CRDHandler) checkAuth(ingress *Ingress) {
	if !AuthzEnabled() {
		return
	}

	// ignore delegate ingresses
	if ingress.Fqdn != "" {
		return
	}

	var authRoute *Route

	for _, route := range ingress.VirtualHost.Routes {
		if route.AuthEnabled() {
			authRoute = route
			break
		}
	}

	if authRoute == nil {
		// delegate doesn't have any routes with auth enabled: nothing to do
		return
	}

	delegators := make(map[*Ingress]struct{})
	recv.mapIngresses(func(ingress2 *Ingress) (stop bool) {
		if ingress2 == ingress {
			return
		}
		if ingress2.TypeURL != ingress.TypeURL {
			return
		}
		if ingress2.Fqdn == "" {
			return
		}
		for _, route := range ingress2.VirtualHost.Routes {
			if route.Delegate == nil {
				continue
			}
			// handle explicit and implicit namespace delegation
			if route.Delegate.Name == ingress.Name &&
				(route.Delegate.Namespace == ingress.Namespace || ingress.Namespace == ingress2.Namespace) {

				delegators[ingress2] = struct{}{}
				break
			}
		}
		return
	})

	if len(delegators) == 0 {
		recv.log.Warn("orphan delegate ingress with auth", "ns", ingress.Namespace, "name", ingress.Name)
		return
	}

	for delegator := range delegators {
		switch {
		case delegator.Listener.TLS == nil:
			recv.log.Warn("invalid delegator: TLS",
				"delegate_ns", ingress.Namespace, "delegate_name", ingress.Name,
				"delegator_ns", delegator.Namespace, "delegator_name", delegator.Name,
			)
			delegator.SetInvalid(fmt.Sprintf("cannot enable delegated route %s/%s authz on non tls listener",
				ingress.Namespace, ingress.Name))
			// track it as a failed delegation so an update will trigger the delegator to re-resolve
			recv.getNS(ingress.Namespace).addFailedDelegation(
				recv.log, ingress.Name,
				recv.getNS(delegator.Namespace).getIngressPtr(delegator),
			)

		case delegator.VirtualHost.Authorization == nil:
			recv.log.Warn("invalid delegator: AuthZ",
				"delegate_ns", ingress.Namespace, "delegate_name", ingress.Name,
				"delegator_ns", delegator.Namespace, "delegator_name", delegator.Name,
			)
			delegator.SetInvalid(fmt.Sprintf("delegated route %s/%s configures authz but %s/%svirtualhost does not",
				ingress.Namespace, ingress.Name, delegator.Namespace, delegator.Name))
			// track it as a failed delegation so an update will trigger the delegator to re-resolve
			recv.getNS(ingress.Namespace).addFailedDelegation(
				recv.log, ingress.Name,
				recv.getNS(delegator.Namespace).getIngressPtr(delegator),
			)
		}
	}
}

// Given a delegator and a delegate, ensure auth is configured properly
func (recv *CRDHandler) delegateAuthValid(delegator, delegate *Ingress) (answer bool) {
	answer = true

	if !AuthzEnabled() {
		return
	}

	if delegator.Listener.TLS != nil && delegator.VirtualHost.Authorization != nil {
		return
	}

	for _, route := range delegate.VirtualHost.Routes {
		if route.AuthEnabled() {
			answer = false
			break
		}
	}
	return
}
