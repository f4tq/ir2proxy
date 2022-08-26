package envoy_api

import (
	"fmt"

	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/util"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	http_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/inconshreveable/log15.v2"
)

// A wrapper around envoy's native authz.ExtAuthz with json marshaling provided by protojson

type HttpExtAuthz struct {
	http_authz.ExtAuthz
}

func init() {
	RegisterPerFilterCreator("envoy.filters.http.ext_authz", func() (interface{}, error) { return NewAuthz(), nil })
}

func NewAuthz() *HttpExtAuthz {
	return &HttpExtAuthz{}
}

// MarshalJSON -- uses protojson to marshall correctly
func (recv *HttpExtAuthz) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*http_authz.ExtAuthz)(&recv.ExtAuthz))
}

// UnmarshalJSON -- uses protojson to marshall correctly
func (recv *HttpExtAuthz) UnmarshalJSON(bb []byte) error {
	return protojson.Unmarshal(bb, (*http_authz.ExtAuthz)(&recv.ExtAuthz))
}
func (recv *HttpExtAuthz) DeepCopy() *HttpExtAuthz {
	rr := HttpExtAuthz{}
	rr.DeepCopyInto(recv)
	return &rr
}
func (recv *HttpExtAuthz) DeepCopyInto(other *HttpExtAuthz) {
	bb, err := other.MarshalJSON()
	if err != nil {
		return
	}
	_ = recv.UnmarshalJSON(bb)
}
func (a HttpExtAuthz) Compare(b HttpExtAuthz) error {
	aa, err := protojson.Marshal(&a)
	if err != nil {
		return fmt.Errorf(".ExtAuth compare error - a marshal error %s", err.Error())
	}
	bb, err := protojson.Marshal(&b)
	if err != nil {
		return fmt.Errorf(".ExtAuth compare error - b marshal error %s", err.Error())
	}
	if string(aa) != string(bb) {
		return fmt.Errorf(".ExtAuth not comparable")
	}
	return nil
}

// DefaultSidecardAuthz Builds the default sidecar auth grpc cluster
func DefaulAuthz() *HttpExtAuthz {
	return BuildAuthz(constants.ExtAuthzCluster)
}

// BuildAuthz -- builds a grps->envoygrpc type HttpExtAuthz given a cluster rname
func BuildAuthz(clustername string) *HttpExtAuthz {
	return &HttpExtAuthz{
		ExtAuthz: http_authz.ExtAuthz{
			FailureModeAllow: true,
			Services: &http_authz.ExtAuthz_GrpcService{
				GrpcService: &core.GrpcService{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
							ClusterName: clustername,
						},
					},
				},
			},
		},
	}
}

// TypedAuthzConfig -- create a HttpFilter from an HttpExtAuthz
func TypedAuthzConfig(log log15.Logger, eaz *HttpExtAuthz) *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: wellknown.HTTPExternalAuthorization,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: util.ToAny(log, eaz),
		},
	}
}
