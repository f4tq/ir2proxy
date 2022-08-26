package v1beta1

import (
	"kapcom.adobe.com/xlate"
)

var _ xlate.TLSCertificateDelegation = &TLSCertificateDelegation{}

func (recv *TLSCertificateDelegation) Delegations() []xlate.CertificateDelegation {
	delegations := make([]xlate.CertificateDelegation, len(recv.Spec.Delegations))
	for i, v := range recv.Spec.Delegations {
		delegations[i] = v
	}
	return delegations
}

func (recv *TLSCertificateDelegation) Name_() string {
	return recv.Name
}

func (recv *TLSCertificateDelegation) Namespace_() string {
	return recv.Namespace
}

func (recv *TLSCertificateDelegation) DeepCopy_() xlate.TLSCertificateDelegation {
	return recv.DeepCopy()
}

func (recv CertificateDelegation) SecretName() string {
	return recv.SecretName_
}

func (recv CertificateDelegation) TargetNamespaces() []string {
	targets := make([]string, len(recv.TargetNamespaces_))
	for i, v := range recv.TargetNamespaces_ {
		targets[i] = v
	}
	return targets
}
