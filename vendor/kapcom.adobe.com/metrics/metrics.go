package metrics

import (
	"context"
	"fmt"
	"net/http"

	"kapcom.adobe.com/config"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/inconshreveable/log15.v2"
)

type (
	// Metrics options
	Flags struct {
		Host             string `long:"host" description:"the IP to listen on" default:"localhost" env:"HOST"`
		Port             int    `long:"port" description:"the port to listen on for insecure connections, defaults to a random value"  env:"PORT"`
		EnvoyCardinality int    `long:"envoy-cardinality" description:"the number of Envoys that should participate in metrics for which their identity contributes to cardinality" default:"10" env:"ENVOY_CARDINALITY"`
	}
)

var Config = &Flags{}

func init() {
	config.AddConfiguration(&config.CommandLineOptionsGroup{
		ShortDescription: "Metrics",
		LongDescription:  "Metrics Flags",
		Namespace:        "metrics",
		EnvNamespace:     "METRICS",
		Options:          Config,
	})
}

func Port() int {
	return Config.Port
}

func Host() string {
	return Config.Host
}

func EnvoyCardinality() int {
	return Config.EnvoyCardinality
}

func ListenAndServe(ctx context.Context, log log15.Logger, exitChan chan<- uint8, flags *Flags) {
	if flags.Port == 0 {
		log.Crit("a metrics port > 0 must be provided")
		exitChan <- 1
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", flags.Host, flags.Port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	log.Info(fmt.Sprintf("Metrics server started on %s:%d", flags.Host, flags.Port))
	defer log.Info(fmt.Sprintf("Metrics server stopped on %s:%d", flags.Host, flags.Port))

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Crit("server.ListenAndServe", "Error", err)
		exitChan <- 1
	}
}

func (recv *Flags) Validate(cfg *config.KapcomConfig) error {
	// TODO(fortescu): implement
	return nil
}

func (recv *Flags) Reset() {
	*recv = Flags{}
}
