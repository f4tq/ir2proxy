package envoy_api

import (
	"fmt"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

// A wrapper around envoy's native route.CorsPolicy with json marshaling provided by protojson

type CorsPolicy struct {
	route.CorsPolicy
}

func init() {
	RegisterPerFilterCreator("envoy.filters.http.cors", func() (interface{}, error) { return NewCorsPolicy(), nil })
}

func NewCorsPolicy() *CorsPolicy {
	return &CorsPolicy{}
}

// MarshalJSON -- uses protojson to marshall correctly
func (recv *CorsPolicy) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*route.CorsPolicy)(&recv.CorsPolicy))
}

// UnmarshalJSON -- uses protojson to marshall correctly
func (recv *CorsPolicy) UnmarshalJSON(bb []byte) error {
	return protojson.Unmarshal(bb, (*route.CorsPolicy)(&recv.CorsPolicy))
}
func (recv *CorsPolicy) DeepCopy() *CorsPolicy {
	rr := CorsPolicy{}
	rr.DeepCopyInto(recv)
	return &rr
}
func (recv *CorsPolicy) DeepCopyInto(other *CorsPolicy) {
	bb, err := other.MarshalJSON()
	if err != nil {
		return
	}
	_ = recv.UnmarshalJSON(bb)
}
func (a CorsPolicy) Compare(b CorsPolicy) error {
	aa, err := protojson.Marshal(&a)
	if err != nil {
		return fmt.Errorf(".CorsPolicy compare error - a marshal error %s", err.Error())
	}
	bb, err := protojson.Marshal(&b)
	if err != nil {
		return fmt.Errorf(".CorsPolicy compare error - b marshal error %s", err.Error())
	}
	if string(aa) != string(bb) {
		return fmt.Errorf(".CorsPolicy not comparable")
	}
	return nil
}
