package util

import (
	"bytes"
	"net"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/ugorji/go/codec"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/inconshreveable/log15.v2"
)

func ToAny(log log15.Logger, msg proto.Message) *any.Any {
	ne, err := ptypes.MarshalAny(msg)
	if err != nil {
		log.Error("ptypes.MarshalAny", "Error", err)
	}
	return ne
}

func FromAny(log log15.Logger, a *any.Any) proto.Message {
	if a == nil {
		log.Debug("util.FromAny a == nil")
		return nil
	}

	var da ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(a, &da); err != nil {
		log.Error("ptypes.UnmarshalAny", "Error", err)
		return nil
	}
	return da.Message
}

func EncodedHeaderValue(value string) string {
	// https://www.envoyproxy.io/docs/envoy/v1.15.0/configuration/http/http_conn_man/headers#custom-request-response-headers
	ret := strings.Replace(value, "%", "%%", -1)
	return strings.Replace(ret, "__percent__", "%", -1)
}

// only works for ipv4
func IP2Uint32(ip net.IP) uint32 {
	var decIP uint32
	if ipv4 := ip.To4(); ipv4 != nil {
		decIP |= uint32(ipv4[0]) << 24
		decIP |= uint32(ipv4[1]) << 16
		decIP |= uint32(ipv4[2]) << 8
		decIP |= uint32(ipv4[3])
	}
	return decIP
}

// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
// Get preferred outbound ip of this machine
func GetOutboundIP(log log15.Logger) net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Crit("net.Dial error", "error", err)
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// SoSEqual compares 2 slices of strings
func SoSEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func Profile(f func()) time.Duration {
	t0 := time.Now()
	f()
	return time.Now().Sub(t0)
}

func AnyTrue(bools ...bool) bool {
	for _, b := range bools {
		if b {
			return true
		}
	}
	return false
}

func AnyFalse(bools ...bool) bool {
	for _, b := range bools {
		if !b {
			return true
		}
	}
	return false
}

func Equal(log log15.Logger, a, b interface{}) (answer bool) {
	hdlA := new(codec.MsgpackHandle)
	hdlA.WriterBufferSize = 1024
	hdlA.Canonical = true

	hdlB := new(codec.MsgpackHandle)
	hdlB.WriterBufferSize = 1024
	hdlB.Canonical = true

	var bufA bytes.Buffer
	var bufB bytes.Buffer

	err := codec.NewEncoder(&bufA, hdlA).Encode(a)
	if err != nil {
		log.Error("encoder.Encode", "Error", err)
		return
	}

	err = codec.NewEncoder(&bufB, hdlB).Encode(b)
	if err != nil {
		log.Error("encoder.Encode", "Error", err)
		return
	}

	answer = bytes.Equal(bufA.Bytes(), bufB.Bytes())
	return
}

// RecurseIface is a *structpb.Value producing function that recurses into nested
// structures
func RecurseIface(s *structpb.Struct, iface interface{}) (ret *structpb.Value) {
	// we ignore errors in types we know do not produce errors
	// (i.e. the matching type in structpb.NewValue's second return is nil)
	switch ifaceVal := iface.(type) {
	case nil:
		ret, _ = structpb.NewValue(iface)
	case bool:
		ret, _ = structpb.NewValue(iface)
	case int:
		ret, _ = structpb.NewValue(iface)
	case int32:
		ret, _ = structpb.NewValue(iface)
	case int64:
		ret, _ = structpb.NewValue(iface)
	case uint:
		ret, _ = structpb.NewValue(iface)
	case uint32:
		ret, _ = structpb.NewValue(iface)
	case uint64:
		ret, _ = structpb.NewValue(iface)
	case float32:
		ret, _ = structpb.NewValue(iface)
	case float64:
		ret, _ = structpb.NewValue(iface)
	case string:
		ret, _ = structpb.NewValue(iface)
	case []byte:
		ret, _ = structpb.NewValue(iface)
	case map[string]interface{}:
		if s == nil { // will only not be nil on the initial call
			s = new(structpb.Struct)
		}
		if s.Fields == nil {
			s.Fields = make(map[string]*structpb.Value)
		}

		for k, v := range ifaceVal {
			s.Fields[k] = RecurseIface(nil, v)
		}

		ret = &structpb.Value{
			Kind: &structpb.Value_StructValue{s},
		}
	case []interface{}:
		lv := new(structpb.ListValue)
		for _, v := range ifaceVal {
			lv.Values = append(lv.Values, RecurseIface(nil, v))
		}
		ret = &structpb.Value{
			Kind: &structpb.Value_ListValue{lv},
		}
	default:
		ret = &structpb.Value{
			Kind: &structpb.Value_NullValue{},
		}
	}
	return
}
