package xlate

import (
	"sort"

	"kapcom.adobe.com/certs"
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/xds"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	k8s "k8s.io/api/core/v1"
)

func secretToTlsCert(secret *k8s.Secret) *tls.TlsCertificate {
	return &tls.TlsCertificate{
		CertificateChain: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{
				InlineBytes: secret.Data[k8s.TLSCertKey],
			},
		},
		PrivateKey: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{
				InlineBytes: secret.Data[k8s.TLSPrivateKeyKey],
			},
		},
	}
}

func (recv *CRDHandler) canMTLS() bool {
	if !config.MTLS() ||
		len(recv.mtls.caSecrets) != 3 ||
		recv.mtls.clientSecret == nil ||
		recv.mtls.serverSecret == nil {
		return false
	}
	return true
}

func (recv *CRDHandler) tryMTLS(secret *k8s.Secret) {
	if secret.Namespace != config.KAPCOMNamespace() {
		return
	}

	var anyUpdate bool

	if certs.CA_RE.MatchString(secret.Name) {
		anyUpdate = true

		recv.mtls.caSecrets = append(recv.mtls.caSecrets, secret)

		sort.Stable(certs.SecretByNumber(recv.mtls.caSecrets))

		if secretsLen := len(recv.mtls.caSecrets); secretsLen > 3 {
			// keep the 3 most recent certs
			recv.mtls.caSecrets = recv.mtls.caSecrets[3+(secretsLen-4):]
		}

		var buf []byte
		// See docs/implementation.md for why these are bundled
		for _, cert := range recv.mtls.caSecrets {
			buf = append(buf, cert.Data[k8s.TLSCertKey]...)
		}
		recv.mtls.caCerts = &tls.CommonTlsContext_ValidationContext{
			ValidationContext: &tls.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: buf,
					},
				},
			},
		}
	} else if certs.ClientRE.MatchString(secret.Name) {
		anyUpdate = true

		recv.mtls.clientSecret = secret
	} else if certs.ServerRE.MatchString(secret.Name) {
		anyUpdate = true

		recv.mtls.serverSecret = secret
	}

	if !anyUpdate {
		return
	}

	// likely waiting for additional certs to sync
	if !recv.canMTLS() {
		return
	}

	for _, sotw := range recv.envoySubsets {
		if sotw.sidecar != nil {
			// handle supporting cluster services
			if RateLimitEnabled() && RateLimitInternalMTLS() {
				// grab pointer to wrapped recv.authzCluster
				rlCluster := RateLimitCluster()
				recv.mutateTransportSocket(rlCluster)
				sotw.cds[RatelimitClusterName()] = recv.rateLimitCluster
				recv.updateSotW(sotw.subset, xds.ClusterType, sotw.cds)
			}
			if AuthzEnabled() && AuthzInternalMTLS() {
				// grab pointer to wrapped recv.authzCluster
				rlCluster := AuthzCluster()
				recv.mutateTransportSocket(rlCluster)
				sotw.cds[AuthzClusterName()] = recv.authzCluster
				recv.updateSotW(sotw.subset, xds.ClusterType, sotw.cds)
			}
		}
		// CGW will be handled in updateCDS and updateLDS
		if sotw.sidecar == nil {
			continue
		}

		ingress := recv.sidecarIngress(sotw.sidecar)
		if ingress == nil {
			continue
		}

		// CGW UpstreamTlsContext
		recv.updateCDS(ingress.Namespace, ingress.Name)

		// Sidecar DownstreamTlsContext
		recv.updateLDS(ingress, nil)
	}
}

func (recv *CRDHandler) mTLSForIngress(ingress *Ingress) *mTLS {
	if !recv.canMTLS() {
		return nil
	}
	recv.log.Debug("mTLSForIngress", "ingress", ingress.Namespace+"/"+ingress.Name)

	for _, sotw := range recv.getSotWs(ingress) {
		// as simple of a check as this it covers our current and future use cases
		//
		// all Ingresses live in a CGW which needs a mTLS-enabled UpstreamTlsContext
		// in CDS
		//
		// all Sidecars either (1) receive traffic from a CGW with an
		// UpstreamTlsContext in CDS and need a symmetrical DownstreamTlsContext
		// on LDS or (2) receive traffic from an ext_authz
		// filter (i.e. Tenant Sidecar to RVS's Sidecar) as a client with a
		// similarly symmetrical UpstreamTlsContext as CGW's CDS's
		//
		// this is by design
		//
		// the simple rule that UpstreamTlsContexts, wherever we have them, get
		// a client cert; and DownstreamTlsContexts, wherever we have them, get
		// a server cert creates symmetry no matter the topology
		if sotw.role == SidecarRole {
			return &recv.mtls
		}
	}

	return nil
}
