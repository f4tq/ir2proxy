package xds

import (
	"time"

	"kapcom.adobe.com/config"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
)

func ConfigSource() *core.ConfigSource {
	var timeout *duration.Duration
	if config.Testing() {
		timeout = ptypes.DurationProto(time.Millisecond)
	} else {
		timeout = ptypes.DurationProto(1 * time.Minute)
	}

	return &core.ConfigSource{
		ConfigSourceSpecifier: &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		},
		InitialFetchTimeout: timeout,
		ResourceApiVersion:  core.ApiVersion_V3,
	}
}
