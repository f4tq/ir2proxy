package envoy_api

import (
	"fmt"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

// Use the full-blown grpc as there aee a million options

type (
	GrpcServices struct {
		*core.GrpcService
	}
)

func init() {
}

// MarshalJSON -- uses protojson to marshall correctly
func (recv *GrpcServices) MarshalJSON() ([]byte, error) {
	return protojson.Marshal((*core.GrpcService)(recv.GrpcService))
}

// UnmarshalJSON -- uses protojson to marshall correctly
func (recv *GrpcServices) UnmarshalJSON(bb []byte) error {
	if recv.GrpcService == nil {
		recv.GrpcService = &core.GrpcService{}
	}
	return protojson.Unmarshal(bb, (*core.GrpcService)(recv.GrpcService))
}
func (recv *GrpcServices) DeepCopy() *GrpcServices {
	rr := GrpcServices{}
	rr.DeepCopyInto(recv)
	return &rr
}
func (recv *GrpcServices) DeepCopyInto(other *GrpcServices) {
	bb, err := other.MarshalJSON()
	if err != nil {
		return
	}
	_ = recv.UnmarshalJSON(bb)
}
func (a GrpcServices) Compare(b GrpcServices) error {
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
