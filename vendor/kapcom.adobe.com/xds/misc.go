package xds

import (
	"os"
	"time"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
)

func ConfigSource() *core.ConfigSource {
	var timeout *duration.Duration
	if config.Testing() {
		if d, err := time.ParseDuration(os.Getenv("initial_fetch_timeout")); err == nil {
			timeout = ptypes.DurationProto(d)
		} else {
			timeout = ptypes.DurationProto(time.Millisecond)
		}
	} else {
		timeout = ptypes.DurationProto(300 * time.Second)
	}

	return &core.ConfigSource{
		ConfigSourceSpecifier: &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		},
		InitialFetchTimeout: timeout,
		ResourceApiVersion:  constants.DefaultApiVersion,
	}
}
