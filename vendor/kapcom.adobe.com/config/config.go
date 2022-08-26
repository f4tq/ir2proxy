package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"kapcom.adobe.com/util"

	flags "github.com/jessevdk/go-flags"
	"gopkg.in/inconshreveable/log15.v2"
)

type (
	CommandLineOptions interface {
		Validate(cfg *KapcomConfig) error
		Reset()
	}
	// CommandLineOptionsGroup represents a group of user-defined command line options
	CommandLineOptionsGroup struct {
		ShortDescription string
		LongDescription  string
		Namespace        string
		EnvNamespace     string
		Options          CommandLineOptions
	}
	KapcomConfig struct {
		CommandLineOptionsGroups []*CommandLineOptionsGroup
		Testing                  Truthy `long:"testing" description:"toggle testing (true|t|yes|y|on|1)" env:"TESTING"  `
		LogDebug                 Truthy `long:"log-debug" description:"log debug (true|t|yes|y|on|1)"   env:"LOG_DEBUG"  `
		LogColor                 Truthy `long:"log-color" description:"log colorize (true|t|yes|y|on|1)"   env:"LOG_COLOR" `

		LogHealthCheckFailures Truthy `long:"log-health-check-failures" description:"log health check failures (true|t|yes|y|on|1)" env:"HC_FAILURE_LOGGING_ENABLED"  `

		WriteCRDStatus       Truthy `long:"write-crd-status" description:"write crd status (true|t|yes|y|on|1)"   env:"WRITE_CRD_STATUS"`
		AdobeEnvoyExtensions Truthy `long:"use-adobe-envoy-extensions" description:"use adobe envoy extensions (true|t|yes|y|on|1)"   env:"ADOBE_ENVOY_EXTENSIONS"`
		MTLS                 Truthy `long:"use-mtls" description:"use-mtls (true|t|yes|y|on|1)" env:"MTLS" `
		MtlsFlags            struct {
			KeyBits     int    `long:"key-bits" env:"KEY_BITS" default:"2048" description:"keys bits used in cert generation"`
			ManageCerts Truthy `long:"manage-certs" description:"create and rotate certs (true|t|yes|y|on|1)" env:"MANAGE_CERTS"`
		} `group:"Mtls" namespace:"mtls" env-namespace:"MTLS" description:"mtls options"`
		KapcomServiceName        string `long:"kapcom-service-name" description:"kapcom service name" default:"kapcom" env:"KAPCOM_SERVICE_NAME"`
		KapcomNamespace          string `long:"kapcom-namespace" description:"kapcom namespace" default:"heptio-contour" env:"KAPCOM_NAMESPACE"`
		KapcomEnvoyConfigDumpUrl string `long:"kapcom-envoy-config-dump-url" description:"envoy config dump url" env:"KAPCOM_ENVOY_CONFIG_DUMP_URL"`

		Contour struct {
			EnvoyConfigDumpUrl string `long:"envoy-config-dump-url" description:"envoy config dump url" env:"ENVOY_CONFIG_DUMP_URL"`
		} `group:"Contour" namespace:"contour" env-namespace:"CONTOUR" description:"contour options"`
		PodIP                  string `long:"pod-ip"  description:"pod ip"  env:"POD_IP"`
		PodIPUint32            uint32
		HostIP                 string        `long:"host-ip" required:"false" description:"host ip"  env:"HOST_IP"`
		SecretRotationInterval time.Duration `long:"secret-rotation-interval" default:"60m" description:"secret rotation interval" env:"SECRET_ROTATION_INTERVAL"`
		Grpc                   struct {
			Tracing Truthy `long:"tracing" env:"TRACING" description:"enable grpc tracing (true|t|yes|y|on|1)"`
			ALS     struct {
				Enabled Truthy `long:"enabled" env:"ENABLED" description:"enable gRPC ALS integration (true|t|yes|y|on|1)"`
			} `group:"als" namespace:"als" env-namespace:"ALS" `
		} `group:"grpc" namespace:"grpc" env-namespace:"GRPC" `
		Kubernetes struct {
			ResyncInterval time.Duration `long:"resync-interval" env:"RESYNC_INTERVAL" description:"re-sync interval"  `
			ServiceHost    string        `long:"service-host" env:"SERVICE_HOST" description:"kubernetes svc host all mysvc.myns.svc.cluster.local"`
		} `group:"Kubernetes" namespace:"k8s" env-namespace:"KUBERNETES" `
		XDS struct {
			Port    int `long:"port"  env:"PORT" default:"3000" description:"The port xds listens on"`
			Backlog int `long:"backlog" env:"BACKLOG" default:"100" description:"The xds channel event length"`
		} `group:"XDS" namespace:"xds" env-namespace:"XDS"`
		Health struct {
			Port int `long:"port"  env:"PORT" default:"3001" description:"The port xds listens on"`
		} `group:"Health" namespace:"health" env-namespace:"HTTP"`
		EnableCRDMigration Truthy `long:"enable-crd-migration" description:"enable-crd-migration (true|t|yes|y|on|1)" env:"ENABLE_CRD_MIGRATION" `
	}
)
type Truthy bool

// UnmarshalFlag -- take an rep of truth
func (m *Truthy) UnmarshalFlag(value string) error {
	switch strings.ToUpper(value) {
	case "1", "T", "TRUE", "YES", "Y", "ON":
		*m = Truthy(true)
	default:
		*m = Truthy(false)
	}
	return nil
}

// MarshalFlag -- emit string value of current truth
func (m *Truthy) MarshalFlag() (string, error) {
	if bool(*m) {
		return "true", nil
	}
	return "false", nil
}
func (m *Truthy) Value() bool {
	return bool(*m)
}

var (
	kapcom *KapcomConfig = newKapcomConfg()
	Log    log15.Logger
)

func init() {
	Log = log15.New()
	// initial parse the environment.
	Parser().ParseArgs([]string{})
	//Info()
}

func newKapcomConfg() *KapcomConfig {
	return &KapcomConfig{
		CommandLineOptionsGroups: make([]*CommandLineOptionsGroup, 0),
	}
}
func Validate() error {
	// TODO: validate any values that may need to be considered togeterh
	for _, oo := range kapcom.CommandLineOptionsGroups {
		if err := oo.Options.Validate(kapcom); err != nil {
			return err
		}
	}
	return nil
}

type pp struct {
	*flags.Parser
}

func (ff *pp) Parse() ([]string, error) {
	va, err := ff.Parser.Parse()
	if err == nil {
		if err := Validate(); err != nil {
			return va, &flags.Error{Type: flags.ErrUnknown, Message: err.Error()}
		}
	}
	return va, err
}
func (ff *pp) ParseArgs(args []string) ([]string, error) {
	va, err := ff.Parser.ParseArgs(args)
	if err == nil {
		if err := Validate(); err != nil {
			return va, &flags.Error{Type: flags.ErrUnknown, Message: err.Error()}
		}
	}
	return va, err
}

type ConfigParser interface {
	Parse() ([]string, error)
	ParseArgs(args []string) ([]string, error)
}

// Parser - returns a parser with all submodule flags embedded
//func Parser() *flags.Parser {
func Parser() ConfigParser {
	parser := flags.NewParser(kapcom, flags.Default)
	parser.NamespaceDelimiter = "-"

	parser.ShortDescription = "kapcom"
	parser.LongDescription = "kapcom programs envoy for cluster-gw and sidecars"
	for _, optsGroup := range kapcom.CommandLineOptionsGroups {
		grp, err := parser.AddGroup(optsGroup.ShortDescription, optsGroup.LongDescription, optsGroup.Options)
		if err != nil {
			panic(err)
		}
		// switch namespace i.e. if option='host', namespace='metrics', then switch is '--metrics-host'
		grp.Namespace = optsGroup.Namespace
		// switch envnamespace i.e. if option='host', envnamespace='METRICS', then envvar is 'METRICS_HOST'
		grp.EnvNamespace = optsGroup.EnvNamespace
	}
	return &pp{
		Parser: parser,
	}
}

// AddConfiguration -- provides way for other package to hook in flags
func AddConfiguration(options *CommandLineOptionsGroup) {
	kapcom.CommandLineOptionsGroups = append(kapcom.CommandLineOptionsGroups, options)
}

func onoff(description string, f func() bool) {
	if f() {
		fmt.Printf("%s: ON\n", description)
	} else {
		fmt.Printf("%s: OFF\n", description)
	}
}
func Info() {
	onoff("gRPC tracing", GrpcTracing)
	onoff("Debug logs", DebugLogs)
	onoff("Colorized logs", ColorizeLogs)
	onoff("Testing", Testing)
	onoff("Writing CRD status", WriteCRDStatus)
	onoff("Adobe Envoy extensions", AdobeEnvoyExtensions)
	onoff("CRD migration", EnableCRDMigration)
	fmt.Println("K8s resync interval:", K8sResyncInterval())
	fmt.Println("Pod IP:", PodIP())
	fmt.Println("Host IP:", HostIP())
	fmt.Println("=============")
}

// Config - config sotw
func Config() *KapcomConfig {
	return kapcom
}

// Reset -- only for use in testing Before/After
func Reset() {
	x := newKapcomConfg()
	x.CommandLineOptionsGroups = kapcom.CommandLineOptionsGroups
	for _, oo := range x.CommandLineOptionsGroups {
		oo.Options.Reset()
	}
	kapcom = x
}

func GrpcTracing() bool {
	return bool(kapcom.Grpc.Tracing)
}

func GrpcAlsEnabled() bool {
	return bool(kapcom.Grpc.ALS.Enabled)
}

func DebugLogs() bool {
	return bool(kapcom.LogDebug)
}

func ColorizeLogs() bool {
	return bool(kapcom.LogColor)
}

func Testing() bool {
	return bool(kapcom.Testing)
}

func K8sResyncInterval() time.Duration {
	return kapcom.Kubernetes.ResyncInterval
}

func InCluster() bool {
	return kapcom.Kubernetes.ServiceHost != ""
}

func WriteCRDStatus() bool {
	return bool(kapcom.WriteCRDStatus)
}

func AdobeEnvoyExtensions() bool {
	return bool(kapcom.AdobeEnvoyExtensions)
}

func LogHealthCheckFailures() bool {
	return bool(kapcom.LogHealthCheckFailures)
}

func MTLS() bool {
	return bool(kapcom.MTLS)
}

func MTLSManageCerts() bool {
	return bool(kapcom.MtlsFlags.ManageCerts)
}

func MTLSKeyBits() int {
	return kapcom.MtlsFlags.KeyBits
}

func KAPCOMEnvoyConfigDumpUrl() string {
	return kapcom.KapcomEnvoyConfigDumpUrl
}

func ContourEnvoyConfigDumpUrl() string {
	return kapcom.Contour.EnvoyConfigDumpUrl
}

func ListenersConfigPath() string {
	return os.Getenv("LISTENERS_CONFIG_PATH")
}

func KAPCOMServiceName() string {
	return kapcom.KapcomServiceName
}

func KAPCOMNamespace() string {
	return kapcom.KapcomNamespace
}

func PodIP() string {
	return kapcom.PodIP
}

func PodIPUint32() uint32 {
	return util.IP2Uint32(net.ParseIP(kapcom.PodIP))
}

func HostIP() string {
	return kapcom.HostIP
}

func SecretRotationInterval() time.Duration {
	return kapcom.SecretRotationInterval
}

func XDSPort() int {
	return kapcom.XDS.Port
}

func HealthPort() int {
	return kapcom.Health.Port
}

func XDSBacklog() int {
	return kapcom.XDS.Backlog
}

func EnableCRDMigration() bool {
	return bool(kapcom.EnableCRDMigration)
}
