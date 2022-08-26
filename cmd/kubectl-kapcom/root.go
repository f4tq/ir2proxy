package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands"
	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands/util"
	_ "github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands/show"
	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands/convert"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	_ "github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // combined authprovider import
	"k8s.io/klog"
	kapcomv1 "kapcom.adobe.com/contour/generated/v1/clientset/versioned"
	kapcomv1beta "kapcom.adobe.com/contour/generated/v1beta/clientset/versioned"
)

var (
	cf      *genericclioptions.ConfigFlags
	kv1b    *kapcomv1beta.Clientset
	kv1     *kapcomv1.Clientset
	streams genericclioptions.IOStreams

	// This variable is populated by goreleaser
	version string
)
/*
// rootCmd represents the base command when called without any subcommands
var rootCmd2 = &cobra.Command{
	Use:          "kubectl-kapcom",
	SilenceUsage: true, // for when RunE returns an error
	Short:        "kapcom ",
	Example:      "kubectl kapcom my_ingress_route_name\n",
	Args:         cobra.MinimumNArgs(0),
	Version:      versionString(),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		restConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		restConfig.QPS = 1000
		restConfig.Burst = 1000

		commands.Kv1b, err = kapcomv1beta.NewForConfig(restConfig)
		if err != nil {
			return fmt.Errorf("failed to construct ingressroute client: %w", err)
		}

		commands.Kv1, err = kapcomv1.NewForConfig(restConfig)
		if err != nil {
			return fmt.Errorf("failed to construct httpproxy client: %w", err)
		}
		return nil
	},
}
*/
var rootCmd = &cobra.Command{
        Use:   "kubectl-kapcom",
        Short: "A kubectl plugin for Adobe kapcom tasks",
        Version:      versionString(),
        PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
                // setup ClientSet clients for kapcom ingressroute and httpproxy
		var err error
		restConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		restConfig.QPS = 1000
		restConfig.Burst = 1000

		commands.Kv1b, err = kapcomv1beta.NewForConfig(restConfig)
		if err != nil {
			return fmt.Errorf("failed to construct ingressroute client: %w", err)
		}

		commands.Kv1, err = kapcomv1.NewForConfig(restConfig)
		if err != nil {
			return fmt.Errorf("failed to construct httpproxy client: %w", err)
		}
		return nil
	},
}


// versionString returns the version prefixed by 'v'
// or an empty string if no version has been populated by goreleaser.
// In this case, the --version flag will not be added by cobra.
func versionString() string {
	if len(version) == 0 {
		return ""
	}
	return "v" + version
}

//IngressRouteToHTTPProxy

func init() {
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

        
	// hide all glog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})

	cf = genericclioptions.NewConfigFlags(true)
        //rootCmd = show.CreateShowRootCommand(cf)
	util.AddNamespacesFlag(rootCmd)

	cf.AddFlags(rootCmd.Flags())
	if err := flag.Set("logtostderr", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set logtostderr flag: %v\n", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(convert.CreateConvertCommand(cf))
}

func main() {
	defer klog.Flush()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
