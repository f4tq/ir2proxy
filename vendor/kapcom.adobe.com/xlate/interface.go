package xlate

type (
	TLSCertificateDelegation interface {
		Name_() string
		Namespace_() string
		DeepCopy_() TLSCertificateDelegation

		Delegations() []CertificateDelegation
	}

	CertificateDelegation interface {
		SecretName() string
		TargetNamespaces() []string
	}
)
