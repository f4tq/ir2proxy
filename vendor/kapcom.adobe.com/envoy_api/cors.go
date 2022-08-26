package envoy_api

import (
	"fmt"

	"kapcom.adobe.com/util"

	cors "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/inconshreveable/log15.v2"
)

// A wrapper around envoy's native CORS with json marshaling provided by protojson

type Cors struct {
	cors.Cors
}

func init() {
	// hcm filter is just a simply struct
	RegisterPerFilterCreator("envoy.filters.http.cors", func() (interface{}, error) { return NewCors(), nil })
}

func NewCors() *Cors {
	return &Cors{}
}

// MarshalJSON -- uses protojson to marshall correctly
func (recv *Cors) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*cors.Cors)(&recv.Cors))
}

// UnmarshalJSON -- uses protojson to marshall correctly
func (recv *Cors) UnmarshalJSON(bb []byte) error {
	return protojson.Unmarshal(bb, (*cors.Cors)(&recv.Cors))
}
func (recv *Cors) DeepCopy() *Cors {
	rr := Cors{}
	rr.DeepCopyInto(recv)
	return &rr
}
func (recv *Cors) DeepCopyInto(other *Cors) {
	bb, err := other.MarshalJSON()
	if err != nil {
		return
	}
	_ = recv.UnmarshalJSON(bb)
}
func (a Cors) Compare(b Cors) error {
	aa, err := protojson.Marshal(&a)
	if err != nil {
		return fmt.Errorf(".Cors compare error - a marshal error %s", err.Error())
	}
	bb, err := protojson.Marshal(&b)
	if err != nil {
		return fmt.Errorf(".Cors compare error - b marshal error %s", err.Error())
	}
	if string(aa) != string(bb) {
		return fmt.Errorf(".Cors not comparable")
	}
	return nil
}

// TypedCorsConfig -- create a HttpFilter from an Cors
func TypedCorsConfig(log log15.Logger, eaz *Cors) *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: wellknown.CORS,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: util.ToAny(log, eaz),
		},
	}
}
