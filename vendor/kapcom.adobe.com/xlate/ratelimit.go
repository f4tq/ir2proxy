package xlate

import (
	"errors"
	"fmt"
	"io/ioutil"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/envoy_api"
	"kapcom.adobe.com/xds"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	ratelimit_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/davecgh/go-spew/spew"
)

type (
	RateLimit = envoy_api.RateLimit

	// RateFlags -- toplevel ratelimit flags.  There are common flags and grpc ServiceConfig flags for envoy or google backend services
	//
	RateFlags struct {
		Enabled config.Truthy         `long:"enable" env:"ENABLE" description:"Enable Ratelimiting"`
		Mtls    config.CertManagement `long:"mtls" env:"MTLS" default:"none" description:"mtls cert managemment.  accepted values: none,internal,external"`

		// Options are many.  It often makes sense to read the filter config from a file
		//    The format follows envoy_v3 proto @typed config ratelimit_http.RateLimit{}
		FilterFromFile      string `long:"filter-file" env:"FILTER_FILE" description:"Read the entire rate-limit filter config from file" `
		ClusterFromFilename string `long:"cluster-file" env:"CLUSTER_FILE" description:"provide a full envoy cluster definition"`

		// filter gets read from FilterFromFile is use
		filter *ratelimit_http.RateLimit
		// cluster rep from file
		cluster *cluster.Cluster
	}
)

var (
	rateLimitFlags = &RateFlags{}
)

func init() {
	// register the config struct
	config.AddConfiguration(&config.CommandLineOptionsGroup{
		ShortDescription: "Rate limit flags",
		LongDescription:  "Ratelimit Flags",
		Namespace:        "rate-limit",
		EnvNamespace:     "RATE_LIMIT",
		Options:          rateLimitFlags})
}

func (flags *RateFlags) Reset() {
	*flags = RateFlags{}
}

// Validate -- top-level validation of ratelimit flags.  Implementation of Config interface
func (flags *RateFlags) Validate(cfg *config.KapcomConfig) error {
	if !flags.Enabled.Value() {
		return nil
	}
	config.Log.Debug(fmt.Sprintf("Rateflags.Validate flags %s\n", spew.Sprint(flags)))
	if len(flags.FilterFromFile) == 0 {
		return errors.New("--rate-limit-filter-file / RATE_LIMIT_FILTER_FILE required")
	}
	bb, err := ioutil.ReadFile(flags.FilterFromFile)
	if err != nil {
		return fmt.Errorf("filter from file error %s", err.Error())
	}
	rr := &ratelimit_http.RateLimit{}
	err = protojson.Unmarshal(bb, rr)
	if err != nil {
		return fmt.Errorf("filter from file error %s", err.Error())
	}
	config.Log.Debug(fmt.Sprintf("RateFlags.Validate file %s read %s\n", flags.FilterFromFile, spew.Sprint(rr)))

	flags.filter = rr

	if len(flags.ClusterFromFilename) == 0 {
		return errors.New("--ratelimit-cluster-file /RATE_LIMIT_CLUSTER_FILE required")
	}
	bb, err = ioutil.ReadFile(flags.ClusterFromFilename)
	if err != nil {
		return fmt.Errorf("EnvoyGrpRatelimitConfig file load error %s", err.Error())
	}
	cluster := &cluster.Cluster{}
	err = protojson.Unmarshal(bb, cluster)
	if err != nil {
		return fmt.Errorf("Cluster marshal error %s", err.Error())
	}
	config.Log.Debug(fmt.Sprintf("Ratelimit.Validate clean cluster file %s\n", spew.Sprint(cluster)))
	flags.cluster = cluster
	switch rateLimitFlags.Mtls {
	case config.Internal:
		if cluster.GetTransportSocket() != nil {
			return fmt.Errorf("ratelimit mtls specifies kapcom managed certs but provides external transport socket")
		}
	case config.External:
		switch {
		case cluster.GetTransportSocket() == nil:
			return fmt.Errorf("ratelimit cluster wants external cert management but does not provide tls context")
		case cluster.GetTransportSocket().Name != "envoy.transport_sockets.tls":
			return fmt.Errorf("ratelimit cluster wants external cert management but does not provide tls context")
		}
		// case None - effectively: don't interfere
	}

	return nil
}

// in -  check where string is in list
func in(item string, list []string) bool {
	for _, ii := range list {
		if ii == item {
			return true
		}
	}
	return false
}

// RateLimitFlags -- external method so accessing rate limit flags
func RateLimitFlags() *RateFlags {
	return rateLimitFlags
}

// RateLimitEnabled -- returns whether rate limiting enabled
func RateLimitEnabled() bool {
	return rateLimitFlags.Enabled.Value()
}

// RatelimitClusterName -- return the Ratelimit cluster name
func RatelimitClusterName() string {
	return rateLimitFlags.cluster.GetName()
}

// RateLimitHcmFilter -- convert the flags settings into the protobuf atelimit_v3.RateLimit struct needed by envoy
func RateLimitHcmFilter(ingress *Ingress) *ratelimit_http.RateLimit {
	if ingress == nil {
		config.Log.Error("RateLimitHcmFilter", "Error", "no ingress")
		return nil
	}
	if ingress.Fqdn == "" {
		config.Log.Error("RateLimitHcmFilter", "Error", "only no top-level domain can have ratelimit")
		return nil
	}
	tmplt := RateLimitHcmFilterDefault()
	if tmplt == nil {
		config.Log.Error("RateLimitHcmFilter", "Error", "No ratelimit default set")
		return nil
	}
	bs, err := protojson.Marshal(RateLimitHcmFilterDefault())
	if err != nil {
		config.Log.Error("RateLimitHcmFilter marshal", "Error", err)
		return nil
	}
	cp := &ratelimit_http.RateLimit{}
	err = protojson.Unmarshal(bs, cp)
	if err != nil {
		config.Log.Error("RateLimitHcmFilter copy", "Error", err)
		return nil
	}
	cp.Domain = ingress.Fqdn
	return cp
}

// RateLimitHcmFilterDefault -- returns the 'template' ratelimit configured at boot
func RateLimitHcmFilterDefault() *ratelimit_http.RateLimit {
	return rateLimitFlags.filter
}

// RateLimitHcmFilter -- convert the flags settings into the protobuf atelimit_v3.RateLimit struct needed by envoy
func RateLimitCluster() *cluster.Cluster {
	return rateLimitFlags.cluster
}
func RateLimitInternalMTLS() bool {
	config.Log.Debug(fmt.Sprintf("RateLimitInternalMTLS rateLimitFlags.Mtls == config.Internal %t", rateLimitFlags.Mtls == config.Internal))

	return rateLimitFlags.Mtls == config.Internal
}

// initRatelimitCluster -- interface to cds that provides a cluster IF the grpc type is envoy
func initRatelimitCluster() (xds.Wrapper, error) {
	return xds.NewWrapper(rateLimitFlags.cluster), nil
}

// RequiresRatelimitFilter -- inspect ingress to determine if ratelimits are in use
func RequiresRatelimitFilter(ingress *Ingress) bool {
	if len(ingress.VirtualHost.RateLimits) > 0 {
		return true
	}
	for _, r := range ingress.VirtualHost.Routes {
		if len(r.RateLimits) > 0 {
			return true
		}

	}
	return false
}

// interface to CRDHandler
func (recv *CRDHandler) initRatelimitCluster() {
	wrap, err := initRatelimitCluster()
	if err != nil {
		recv.log.Error(fmt.Sprintf("rateLimit init error %s", err.Error()))
		return
	}
	recv.rateLimitCluster = wrap
}
