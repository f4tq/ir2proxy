package xlate

import (
	go_tls "crypto/tls"
	"crypto/x509"
	"reflect"

	"kapcom.adobe.com/xds"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	k8s "k8s.io/api/core/v1"
)

func (recv *CRDHandler) removeUnreferencedSecrets(ingress *Ingress) {
	if ingress.Listener.TLS == nil ||
		ingress.Listener.TLS.SecretName == "" {
		// this Ingress doesn't reference a secret
		return
	}
	deletedSecretName := ingress.Listener.TLS.SecretName

	// fast path if this is the default cert
	ic, exists := recv.lc.IngressClasses[ingress.Class]
	if exists && deletedSecretName == ic.DefaultCert {
		return
	}

	recv.removeUnreferencedSecretByName(deletedSecretName)
}

func (recv *CRDHandler) removeUnreferencedSecretByName(deletedSecretName string) (removed bool) {

	var referenced bool
	recv.mapIngresses(func(ingress *Ingress) (stop bool) {
		if ingress.Listener.TLS == nil || ingress.Listener.TLS.SecretName == "" {
			return
		}
		existingSecretName := ingress.Listener.TLS.SecretName

		if deletedSecretName == existingSecretName {
			referenced = true
			stop = true
		}
		return
	})

	if referenced {
		return
	}

	sotw := recv.envoySubsets[xds.DefaultEnvoySubset]
	if _, exists := sotw.sds[deletedSecretName]; exists {
		delete(sotw.sds, deletedSecretName)
		recv.updateSotW(xds.DefaultEnvoySubset, xds.SecretType, sotw.sds)
	}

	removed = true
	return
}

func (recv *CRDHandler) updateSDS(iface, ifaceOld interface{}) {
	var (
		exists              bool
		referenced          bool
		secretName          string
		tlsCert, tlsKey     []byte
		kSecret, kSecretOld *k8s.Secret
		ingress, ingressOld *Ingress
	)

	sotw := recv.envoySubsets[xds.DefaultEnvoySubset]

	switch crd := iface.(type) {

	case *Ingress:
		ingress = crd
		if ifaceOld != nil {
			ingressOld = ifaceOld.(*Ingress)
		}

	case *k8s.Secret:
		kSecret = crd
		if ifaceOld != nil {
			kSecretOld = ifaceOld.(*k8s.Secret)
		}

	default:
		recv.log.Error("updateSDS received unknown type",
			"TypeOf", reflect.TypeOf(iface).String())
		return
	}

	if ingress != nil {
		if ingress.Listener.TLS == nil ||
			ingress.Listener.TLS.SecretName == "" {
			// this Ingress doesn't reference a secret
			return
		}

		if ingressOld != nil {
			lstnr := ingress.Listener
			lstnrOld := ingressOld.Listener
			if lstnr.TLS != nil && lstnrOld.TLS != nil &&
				lstnr.TLS.SecretName == lstnrOld.TLS.SecretName {
				// the SecretName hasn't changed
				return
			}
		}

		secretName = ingress.Listener.TLS.SecretName
		if kSecret, exists = recv.secrets[secretName]; exists {
			referenced = true
		} else {
			// we haven't been informed of the Secret yet
			return
		}
		// at this point secretName and kSecret are populated

		if _, exists := sotw.sds[secretName]; exists {
			// the Secret is already in SDS SotW and this is not a Secret update
			return
		}
		// at this point SDS SotW needs updated now that an Ingress references it
	}

	secretName = SecretsKey(kSecret)

	if !referenced {
		// fast path if this Secret is the DefaultCert for a Listener
		for _, ic := range recv.lc.IngressClasses {
			if ic.DefaultCert == secretName {
				referenced = true
				break
			}
		}
	}

	// we have a kSecret and need to find out if any Ingress references it
	if !referenced {
		recv.mapIngresses(func(ingress *Ingress) (stop bool) {
			lstnr := ingress.Listener
			if lstnr.TLS == nil || lstnr.TLS.SecretName == "" {
				return
			}

			if secretName == lstnr.TLS.SecretName {
				referenced = true
				stop = true
			}
			return
		})
	}

	if !referenced {
		// we've been informed of a Secret that no Ingress or Listener references
		return
	}

	if _, exists = sotw.sds[secretName]; exists && kSecretOld == nil {
		// the Secret is referenced, in the SDS SotW, and this is not an update
		// no necessarily: see https://git.corp.adobe.com/adobe-platform/kapcom/issues/182
		// TODO(lrouquet): need to think about this some more
		// return
	}

	tlsCert, exists = kSecret.Data[k8s.TLSCertKey]
	if !exists {
		recv.log.Error("missing "+k8s.TLSCertKey, "secret", secretName)
		return
	}

	tlsKey, exists = kSecret.Data[k8s.TLSPrivateKeyKey]
	if !exists {
		recv.log.Error("missing "+k8s.TLSPrivateKeyKey, "secret", secretName)
		return
	}

	cert, err := go_tls.X509KeyPair(tlsCert, tlsKey)
	if cert.Leaf != nil || err != nil {
		recv.log.Warn("invalid X509KeyPair", "secret", secretName, "Error", err)
		return
	}

	for _, xCert := range cert.Certificate {
		x509Cert, err := x509.ParseCertificate(xCert)
		if err != nil {
			recv.log.Warn("certificate parsing failure", "secret", secretName, "Error", err)
			return
		}
		// Envoy only considers DNSNames, IPAddresses and URIs as valid SAN values (but not EmailAddresses)
		// https://github.com/envoyproxy/envoy/blob/v1.16.2/source/extensions/transport_sockets/tls/context_impl.cc#L1167-L1185
		if x509Cert.Subject.CommonName == "" &&
			len(x509Cert.DNSNames) == 0 && len(x509Cert.IPAddresses) == 0 && len(x509Cert.URIs) == 0 {
			recv.log.Warn("invalid certificate", "secret", secretName, "Error", "no subject CN nor SAN")
			return
		}
	}

	var wrapper xds.Wrapper
	if iface, exists := sotw.sds[secretName]; exists {
		wrapper = iface.(xds.Wrapper)
	} else {
		wrapper = xds.NewWrapper(&tls.Secret{})
		sotw.sds[secretName] = wrapper
	}

	tlsSecret := &tls.Secret{
		Name: secretName,
		Type: &tls.Secret_TlsCertificate{
			TlsCertificate: &tls.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: tlsCert,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: tlsKey,
					},
				},
			},
		},
	}

	if wrapper.CompareAndReplace(recv.log, tlsSecret) {
		recv.updateSotW(xds.DefaultEnvoySubset, xds.SecretType, sotw.sds)
	}
}
