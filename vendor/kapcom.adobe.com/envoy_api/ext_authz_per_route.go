package envoy_api

import (
	"encoding/json"
	"errors"
	"fmt"
	http_authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	// converter registered with envoy_api
	authrouteconverter = &extAuthRouteConverter{}
)

type (
	extAuthRouteConverter struct {
	}

	ExtAuthzPerRoute struct {
		http_authz.ExtAuthzPerRoute
	}
)

func init() {
	// register the converter with envoy_api
	RegisterFilterConverter(authrouteconverter)
	// Perfilters "envoy.config.filter.http.ext_authz.v2.ExtAuthzPerRoute
	// this is for the canonical 'official' ExtAuthzPerRoute struct (proto)
	f := func() (interface{}, error) { return &ExtAuthzPerRoute{}, nil }
	RegisterPerFilterCreator("http.ext_authz.v3.ExtAuthzPerRoute", f)
	RegisterPerFilterCreator("envoy.filters.http.ext_authz", f)
	//"type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute"
	RegisterPerFilterCreator("type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
		func() (interface{}, error) { return &ExtAuthzPerRoute{}, nil })

}

// MarshalJSON -- uses protojson to marshall correctly
func (recv *ExtAuthzPerRoute) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*http_authz.ExtAuthzPerRoute)(&recv.ExtAuthzPerRoute))
}

// UnmarshalJSON -- uses protojson to marshall correctly
func (recv *ExtAuthzPerRoute) UnmarshalJSON(bb []byte) error {
	return protojson.Unmarshal(bb, (*http_authz.ExtAuthzPerRoute)(&recv.ExtAuthzPerRoute))
}
func (recv *ExtAuthzPerRoute) DeepCopy() *ExtAuthzPerRoute {
	rr := ExtAuthzPerRoute{}
	rr.DeepCopyInto(recv)
	return &rr
}
func (recv *ExtAuthzPerRoute) DeepCopyInto(other *ExtAuthzPerRoute) {
	bb, err := other.MarshalJSON()
	if err != nil {
		return
	}
	_ = recv.UnmarshalJSON(bb)
}
func (a ExtAuthzPerRoute) Compare(b ExtAuthzPerRoute) error {
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

// filter type converter

// Type -- the converter type
func (recv *extAuthRouteConverter) Type() string {
	return "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute"
}

// String -- same a type but useful in string contexts
func (recv *extAuthRouteConverter) String() string { return recv.Type() }

// Unmarshal -- read a protojson rep of proto ratelimit_http.RateLimit
func (recv *extAuthRouteConverter) Unmarshal(bb []byte) (interface{}, error) {
	xx := http_authz.ExtAuthzPerRoute{}
	err := protojson.Unmarshal(bb, &xx)
	if err != nil {
		return nil, err
	}
	return &xx, nil
}

// Alias proto ratelimit_http Ratelimit so the Marshal will insert envoy @type
//   - don not confuse with route_v3.Ratelimit.
type AuthzRouteAlias http_authz.ExtAuthzPerRoute

// MarshalJSON -- uses protojson to marshall correctly
func (recv *AuthzRouteAlias) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*http_authz.ExtAuthzPerRoute)(recv))
}

// Marshal @type type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit"
func (recv *extAuthRouteConverter) Marshal(data interface{}) ([]byte, error) {
	ty, ok := data.(*http_authz.ExtAuthzPerRoute)
	if !ok {
		return nil, errors.New("marshal failed: not *http_authz.ExtAuthzPerRoute")
	}
	xx := struct {
		Type string `json:"@type,omitempty"`
		*AuthzRouteAlias
	}{
		Type:            recv.Type(),
		AuthzRouteAlias: (*AuthzRouteAlias)(ty),
	}
	return json.Marshal(&xx)
}
func (recv *extAuthRouteConverter) Compare(a interface{}, b interface{}) error {
	A, ok := a.(*http_authz.ExtAuthzPerRoute)
	if !ok {
		return errors.New("Compare failed: not *http_authz.ExtAuthzPerRoute")
	}
	B, ok := a.(*http_authz.ExtAuthzPerRoute)
	if !ok {
		return errors.New("Compare failed: not *http_authz.ExtAuthzPerRoute")
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
