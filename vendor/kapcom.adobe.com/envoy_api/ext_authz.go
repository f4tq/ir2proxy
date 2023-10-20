package envoy_api

import (
	"fmt"

	"kapcom.adobe.com/constants"

	http_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"google.golang.org/protobuf/encoding/protojson"
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
	err := protojson.Unmarshal(bb, (*http_authz.ExtAuthz)(&recv.ExtAuthz))
	if err != nil {
		return err
	}
	recv.ExtAuthz.TransportApiVersion = constants.DefaultApiVersion
	return nil
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
