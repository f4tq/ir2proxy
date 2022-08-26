package certs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"time"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
	"kapcom.adobe.com/constants/annotations"
	"kapcom.adobe.com/types"

	"gopkg.in/inconshreveable/log15.v2"
	k8s "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	client_core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

type (
	Manager struct {
		log          log15.Logger
		timeProvider types.TimeProvider
		leader       types.Leader
		api          types.SecretsApi
	}

	k8sSecretsApi struct {
		client client_core.SecretInterface
	}
)

var (
	CA_RE    = regexp.MustCompile(`^mtls-ca-\d+$`)
	ClientRE = regexp.MustCompile(`^mtls-client-\d+$`)
	ServerRE = regexp.MustCompile(`^mtls-server-\d+$`)
	numRE    = regexp.MustCompile(`(\d+)$`)
)

func NewK8sSecretsApi(log log15.Logger) (api types.SecretsApi) {
	conf, err := rest.InClusterConfig()
	if err != nil {
		log.Crit("rest.InClusterConfig", "Error", err)
		return
	}

	k8s, err := kubernetes.NewForConfig(conf)
	if err != nil {
		log.Crit("kubernetes.NewForConfig", "Error", err)
		return
	}

	api = &k8sSecretsApi{
		client: k8s.CoreV1().Secrets(config.KAPCOMNamespace()),
	}
	return
}

func NewManager(log log15.Logger, leader types.Leader, api types.SecretsApi,
	timeProvider types.TimeProvider) *Manager {

	return &Manager{
		log:          log,
		timeProvider: timeProvider,
		leader:       leader,
		api:          api,
	}
}

func CAName(n uint16) string {
	return fmt.Sprintf("mtls-ca-%v", n)
}

func ClientName(n uint16) string {
	return fmt.Sprintf("mtls-client-%v", n)
}

func ServerName(n uint16) string {
	return fmt.Sprintf("mtls-server-%v", n)
}

type SecretByNumber []*k8s.Secret

func (recv SecretByNumber) Len() int {
	return len(recv)
}
func (recv SecretByNumber) Less(i, j int) bool {
	iMatch := numRE.FindAllString(recv[i].Name, -1)
	jMatch := numRE.FindAllString(recv[j].Name, -1)
	if len(iMatch) == 1 && len(jMatch) == 1 {
		iInt, iErr := strconv.Atoi(iMatch[0])
		jInt, jErr := strconv.Atoi(jMatch[0])
		if iErr == nil && jErr == nil {

			if iInt == math.MaxUint16 || iInt == math.MaxUint16-1 {
				if jInt == 0 || jInt == 1 {
					return true
				}
			} else if jInt == math.MaxUint16 || jInt == math.MaxUint16-1 {
				if iInt == 0 || iInt == 1 {
					return true
				}
			}

			return iInt < jInt
		}
	}
	return true
}
func (recv SecretByNumber) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

func nextCertNum(secrets []*k8s.Secret) (num uint16) {
	for _, secret := range secrets {
		matches := numRE.FindAllString(secret.Name, -1)
		if len(matches) > 0 {
			if i, _ := strconv.Atoi(matches[0]); uint16(i) > num {
				num = uint16(i)
			}
		}
	}
	num += 1
	return
}

func (recv *k8sSecretsApi) Create(secret *k8s.Secret, opts meta.CreateOptions) (*k8s.Secret, error) {
	return recv.client.Create(context.Background(), secret, opts)
}

func (recv *k8sSecretsApi) Delete(name string, opts meta.DeleteOptions) error {
	return recv.client.Delete(context.Background(), name, opts)
}

func (recv *k8sSecretsApi) List(opts meta.ListOptions) (*k8s.SecretList, error) {
	return recv.client.List(context.Background(), opts)
}

func (recv *Manager) newCACert(name string) (secret *k8s.Secret) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Issuer: pkix.Name{
			Organization: []string{constants.ProgramNameUpper},
			CommonName:   constants.MTLSCA,
		},
		Subject: pkix.Name{
			Organization: []string{constants.ProgramNameUpper},
			CommonName:   constants.MTLSCA,
		},
		NotBefore:             recv.timeProvider.Now().Add(-time.Hour), // correct for possible clock skew
		NotAfter:              recv.timeProvider.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caKey, err := rsa.GenerateKey(rand.Reader, config.MTLSKeyBits())
	if err != nil {
		recv.log.Error("rsa.GenerateKey", "Error", err)
		return
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		recv.log.Error("x509.CreateCertificate", "Error", err)
		return
	}

	caCertPEM := new(bytes.Buffer)
	pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caKeyPEM := new(bytes.Buffer)
	pem.Encode(caKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	secret = &k8s.Secret{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: config.KAPCOMNamespace(),
			Annotations: map[string]string{
				annotations.CreatedEpoch: fmt.Sprintf("%v", recv.timeProvider.Now().Unix()),
			},
		},
		Data: map[string][]byte{
			k8s.TLSCertKey:       caCertPEM.Bytes(),
			k8s.TLSPrivateKeyKey: caKeyPEM.Bytes(),
		},
		Type: k8s.SecretTypeTLS,
	}
	return
}

func (recv *Manager) newCert(name string, caSecret *k8s.Secret) (secret *k8s.Secret) {

	block, rest := pem.Decode(caSecret.Data[k8s.TLSCertKey])
	if block == nil {
		recv.log.Error("pem.Decode", "caSecret", caSecret.Name, "rest", string(rest))
		return
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		recv.log.Error("x509.ParseCertificate", "Error", err)
		return
	}

	block, rest = pem.Decode(caSecret.Data[k8s.TLSPrivateKeyKey])
	if block == nil {
		recv.log.Error("pem.Decode", "caSecret", caSecret.Name, "rest", string(rest))
		return
	}
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		recv.log.Error("x509.ParsePKCS1PrivateKey", "Error", err)
		return
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Issuer: pkix.Name{
			Organization: []string{constants.ProgramNameUpper},
			CommonName:   constants.MTLSCA,
		},
		Subject: pkix.Name{
			Organization: []string{constants.ProgramNameUpper},
			CommonName:   constants.ProgramNameUpper + " cert",
		},
		NotBefore: recv.timeProvider.Now().Add(-time.Hour), // correct for possible clock skew
		NotAfter:  recv.timeProvider.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	certKey, err := rsa.GenerateKey(rand.Reader, config.MTLSKeyBits())
	if err != nil {
		recv.log.Error("rsa.GenerateKey", "Error", err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		recv.log.Error("x509.CreateCertificate", "Error", err)
		return
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	secret = &k8s.Secret{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: config.KAPCOMNamespace(),
		},
		Data: map[string][]byte{
			k8s.TLSCertKey:       certPEM.Bytes(),
			k8s.TLSPrivateKeyKey: keyPEM.Bytes(),
		},
		Type: k8s.SecretTypeTLS,
	}
	return
}

func (recv *Manager) rotateCerts(certs []*k8s.Secret, kind string, nameFunc func(uint16) string, ca *k8s.Secret) (certsRet []*k8s.Secret) {
	certsLen := len(certs)
	for i := 0; i < 3-certsLen; i++ {
		certName := nameFunc(nextCertNum(certs))
		recv.log.Info("creating "+kind+" cert", "name", certName)
		cert := recv.newCert(certName, ca)
		if cert == nil {
			return
		}
		certs = append(certs, cert)
		if _, err := recv.api.Create(cert, meta.CreateOptions{}); err != nil {
			recv.log.Error("Create secret failed", "Error", err)
			return
		}
	}

	// on initial creation do not also continue to rotate
	if certsLen == 0 {
		return
	}

	if len(certs) < 3 {
		recv.log.Error("could not create " + kind + " certs")
		return
	}

	sort.Stable(SecretByNumber(certs))

	oldestCert := certs[0]
	newCert := recv.newCert(nameFunc(nextCertNum(certs)), ca)
	if newCert == nil {
		return
	}
	recv.log.Info(kind+" rotation", "oldest", oldestCert.Name, "new", newCert.Name)

	if _, err := recv.api.Create(newCert, meta.CreateOptions{}); err != nil {
		recv.log.Error("Create secret failed", "Error", err)
		return
	}
	certs = append(certs, newCert)

	// prior failed deletions could leave us with more than a single old cert to delete
	for _, cert := range certs[:len(certs)-3] {
		recv.log.Info("deleting "+kind+" cert", "name", cert.Name)
		if err := recv.api.Delete(cert.Name, meta.DeleteOptions{}); err != nil {
			recv.log.Error("Delete secret failed", "Error", err)
			// don't return. we have at least created what we need
		}
	}

	certsRet = certs
	return
}

func (recv *Manager) Rotate() {
	if recv.leader.InCharge() != types.Yes {
		return
	}

	recv.log.Info("secret rotation interval. checking certs")

	list, err := recv.api.List(meta.ListOptions{
		FieldSelector: "type=" + string(k8s.SecretTypeTLS),
	})
	if err != nil {
		recv.log.Error("List secrets", "Error", err)
		return
	}

	var (
		caCerts     []*k8s.Secret
		clientCerts []*k8s.Secret
		serverCerts []*k8s.Secret
	)

	for i, secret := range list.Items {
		// secret is a value that's already been copied as part of iteration
		// which is why we use &list.Items[i] to get the pointer of the original
		// value
		if CA_RE.MatchString(secret.Name) {
			caCerts = append(caCerts, &list.Items[i])
		} else if ClientRE.MatchString(secret.Name) {
			clientCerts = append(clientCerts, &list.Items[i])
		} else if ServerRE.MatchString(secret.Name) {
			serverCerts = append(serverCerts, &list.Items[i])
		}
	}

	caCertsLen := len(caCerts)
	for i := 0; i < 3-caCertsLen; i++ {
		caCertName := CAName(nextCertNum(caCerts))
		recv.log.Info("creating CA cert", "name", caCertName)
		caCert := recv.newCACert(caCertName)
		if caCert == nil {
			return
		}
		caCerts = append(caCerts, caCert)
		if _, err = recv.api.Create(caCert, meta.CreateOptions{}); err != nil {
			recv.log.Error("Create secret failed", "Error", err)
			return
		}
	}

	if len(caCerts) < 3 {
		recv.log.Error("could not create CA certs")
		return
	}

	sort.Stable(SecretByNumber(caCerts))

	oldestCAEpoch, err := strconv.ParseInt(caCerts[0].Annotations[annotations.CreatedEpoch], 10, 64)
	if err != nil {
		recv.log.Error("strconv.Atoi", "Error", err,
			annotations.CreatedEpoch, caCerts[0].Annotations[annotations.CreatedEpoch])
	}

	durationSinceLastRotation := time.Duration(recv.timeProvider.Now().Unix()-oldestCAEpoch) * time.Second

	if durationSinceLastRotation > config.SecretRotationInterval() {
		recv.log.Info("rotating CA certs")
		oldestCACert := caCerts[0]
		newCACert := recv.newCACert(CAName(nextCertNum(caCerts)))
		if newCACert == nil {
			return
		}
		recv.log.Info("CA rotation", "oldest", oldestCACert.Name, "new", newCACert.Name)

		if _, err = recv.api.Create(newCACert, meta.CreateOptions{}); err != nil {
			recv.log.Error("Create secret failed", "Error", err)
			return
		}
		caCerts = append(caCerts, newCACert)

		// prior failed deletions could leave us with more than a single old cert to delete
		oldCACerts := caCerts[:len(caCerts)-3]
		caCerts = caCerts[len(caCerts)-3:]
		for _, cert := range oldCACerts {
			recv.log.Info("deleting CA cert", "name", cert.Name)
			if err = recv.api.Delete(cert.Name, meta.DeleteOptions{}); err != nil {
				recv.log.Error("Delete secret failed", "Error", err)
			}
		}

		// uint16 rollover means what was appended above might need to go first
		sort.Stable(SecretByNumber(caCerts))

		// See docs/implementation.md for why the second cert is used
		clientCerts = recv.rotateCerts(clientCerts, "Client", ClientName, caCerts[1])
		serverCerts = recv.rotateCerts(serverCerts, "Server", ServerName, caCerts[1])
	}

	if len(clientCerts) < 3 {
		recv.rotateCerts(clientCerts, "Client", ClientName, caCerts[1])
	}

	if len(serverCerts) < 3 {
		recv.rotateCerts(serverCerts, "Server", ServerName, caCerts[1])
	}

	for _, caCert := range caCerts {
		recv.log.Debug("caCert", "name", caCert.Name, "data", len(caCert.Data))
	}
}

func (recv *Manager) Loop(ctx context.Context) {
	t := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// rotation can take awhile and if we reset the timer first we'll
			// come back and the timer will already have expired
			recv.Rotate()
			t.Reset(time.Minute)
		}
	}
}
