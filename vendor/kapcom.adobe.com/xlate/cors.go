package xlate

import (
	cors "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
)

type (
	CorsFlags struct {
		filter *cors.Cors
	}
)

var (
	corsFlags = &CorsFlags{
		filter: &cors.Cors{},
	}
)

// CORSHcmFilter -- one cors hcm filter
func CorsHcmFilter() *cors.Cors {
	if corsFlags.filter != nil {
		return corsFlags.filter
	}
	corsFlags.filter = &cors.Cors{}
	return corsFlags.filter
}
