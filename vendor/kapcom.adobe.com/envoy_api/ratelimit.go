package envoy_api

import (
	"encoding/json"
	"errors"
	"fmt"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ratelimit_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

// types in this file mirror critical envoy types
// that are best used as except for the weak json rendering needed to fully utilize and not duplicate
// envoy types

var (
	// converter registered with envoy_api
	converter = &filterConverter{}
)

type (
	RateLimit struct {
		*route.RateLimit
	}
	// filterConverter - stub for defining Ratelimit httpfilterconfig transforms
	filterConverter struct {
	}
)

func init() {

	// register the converter with envoy_api
	RegisterFilterConverter(converter)

}
func NewRateLimit() *RateLimit {
	return &RateLimit{
		RateLimit: &route.RateLimit{},
	}
}

// MarshalJSON -- uses protojson to marshall correctly
func (recv *RateLimit) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*route.RateLimit)(recv.RateLimit))
}

// UnmarshalJSON -- uses protojson to marshall correctly
func (recv *RateLimit) UnmarshalJSON(bb []byte) error {
	if recv.RateLimit == nil {
		recv.RateLimit = &route.RateLimit{}
	}
	return protojson.Unmarshal(bb, (*route.RateLimit)(recv.RateLimit))
}
func (recv *RateLimit) DeepCopy() *RateLimit {
	rr := RateLimit{}
	rr.DeepCopyInto(recv)
	return &rr
}
func (recv *RateLimit) DeepCopyInto(other *RateLimit) {
	bb, err := other.MarshalJSON()
	if err != nil {
		return
	}
	_ = recv.UnmarshalJSON(bb)
}

// filter type converter

// Type -- the converter type
func (recv *filterConverter) Type() string {
	return "type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit"
}

// String -- same a type but useful in string contexts
func (recv *filterConverter) String() string { return recv.Type() }

// Unmarshal -- read a protojson rep of proto ratelimit_http.RateLimit
func (recv *filterConverter) Unmarshal(bb []byte) (interface{}, error) {
	xx := ratelimit_http.RateLimit{}
	err := protojson.Unmarshal(bb, &xx)
	if err != nil {
		return nil, err
	}
	return &xx, nil
}

// Alias proto ratelimit_http Ratelimit so the Marshal will insert envoy @type
//   - don not confuse with route_v3.Ratelimit.
type Alias ratelimit_http.RateLimit

// MarshalJSON -- uses protojson to marshall correctly
func (recv *Alias) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*ratelimit_http.RateLimit)(recv))
}

// Marshal @type type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit"
func (recv *filterConverter) Marshal(data interface{}) ([]byte, error) {
	ty, ok := data.(*ratelimit_http.RateLimit)
	if !ok {
		return nil, errors.New("marshal failed: not *ratelimit_http.RateLimit")
	}
	xx := struct {
		Type string `json:"@type,omitempty"`
		*Alias
	}{
		Type:  recv.Type(),
		Alias: (*Alias)(ty),
	}
	return json.Marshal(&xx)
}
func (recv *filterConverter) Compare(a interface{}, b interface{}) error {
	A, ok := a.(*ratelimit_http.RateLimit)
	if !ok {
		return errors.New("Compare failed: not *ratelimit_http.RateLimit")
	}
	B, ok := a.(*ratelimit_http.RateLimit)
	if !ok {
		return errors.New("Compare failed: not *ratelimit_http.RateLimit")
	}
	ax, err := protojson.Marshal(A)
	if err != nil {
		return fmt.Errorf("Compared failed serializing A %s", err.Error())
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
