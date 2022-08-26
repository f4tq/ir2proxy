package xlate

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"

	"kapcom.adobe.com/constants"

	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	k8s "k8s.io/api/core/v1"
)

type ClusterNameOpts int

const (
	OptNoHash ClusterNameOpts = 1 << iota
)

func ClusterName(cluster *Cluster, kService *k8s.Service, kServicePort *k8s.ServicePort, opts ...ClusterNameOpts) string {
	doHash := true
	for _, opt := range opts {
		if opt&OptNoHash > 0 {
			doHash = false
		}
	}

	list := []string{
		kService.Namespace,
		kService.Name,
		fmt.Sprintf("%v", kServicePort.Port),
	}

	if doHash {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		// ignore "weight" in the encoding
		if cluster.Weight == nil {
			enc.Encode(cluster)
		} else {
			tmpCluster := cluster.DeepCopy()
			tmpCluster.Weight = nil
			enc.Encode(tmpCluster)
		}

		crc := crc32.Checksum(buf.Bytes(), crc32.IEEETable)
		list = append(list, fmt.Sprintf("%v", crc))
	}

	return strings.Join(list, constants.XDSDelimiter)
}

func AltStatName(kService *k8s.Service, kServicePort *k8s.ServicePort) string {
	return strings.Join([]string{
		kService.Namespace,
		kService.Name,
		strconv.Itoa(int(kServicePort.Port)),
	}, "_")
}

func GRPCClusterName(grpc *GRPCLogger) string {
	return "gRPC-ALS@" + grpc.Host + ":" + strconv.Itoa(int(grpc.Port))
}

// TLSProtocolVersion parses a tls version string into a its protobuf equivalent
// it returns false if the input string doesn't match any known version
func TLSProtocolVersion(version string) (bool, tls.TlsParameters_TlsProtocol) {
	var tlsVersion tls.TlsParameters_TlsProtocol
	ret := true
	switch version {
	case "1.0":
		tlsVersion = tls.TlsParameters_TLSv1_0
	case "1.1":
		tlsVersion = tls.TlsParameters_TLSv1_1
	case "1.2":
		tlsVersion = tls.TlsParameters_TLSv1_2
	case "1.3":
		tlsVersion = tls.TlsParameters_TLSv1_3
	default:
		tlsVersion = tls.TlsParameters_TLS_AUTO
		ret = false
	}
	return ret, tlsVersion
}

func arr2map(arr []string) map[string]struct{} {
	ret := make(map[string]struct{})
	for _, elem := range arr {
		if key := strings.Trim(elem, " "); len(key) > 0 {
			ret[key] = struct{}{}
		}
	}
	return ret
}
