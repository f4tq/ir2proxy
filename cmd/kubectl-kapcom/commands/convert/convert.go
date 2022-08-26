package convert

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands"
	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands/util"
	"github.com/projectcontour/ir2proxy/internal/translator"

	"github.com/spf13/cobra"
	_ "github.com/spf13/viper"
	"github.com/tidwall/sjson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // combined authprovider import
	"k8s.io/klog"
	"sigs.k8s.io/yaml"
)

// CreateConvertCommand creates and returns this cobra subcommand
func CreateConvertCommand(flags *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ir2proxy",
		Short: "ir2proxy transforms ingressroute into httpproxy",
		Example: `
		#
		kubectl kapcom ir2proxy -A
		kubectl kapcom ir2proxy -n monitoring grafana`,
		RunE: func(cmd *cobra.Command, args []string) error {
			util.PrintError(transform(flags, cmd, args))
			return nil
		},
	}
	util.AddNamespacesFlag(cmd)
	cmd.Flags().Bool(commands.ApplyFlag, false, "Transform all ingressroutes to httpproxy in place")
	cmd.Flags().StringP("namespace", "n", "", "namespace")

	return cmd
}

// neatYaml -- helper that removes kubernetes injected keys from given object's yaml rep
func neatYaml(ir interface{}, debug bool) ([]byte, error) {
	vraw, err := json.Marshal(ir)
	if err != nil {
		return nil, fmt.Errorf("failed to construct httpproxy client: %w", err)
	}
	v2 := string(vraw)

	for _, item := range commands.Neat {

		vint, err := sjson.Delete(v2, item)
		if err != nil {
			return nil, fmt.Errorf("failed to delete path %s: %w", item, err)
		}
		v2 = vint
	}

	return yaml.JSONToYAML([]byte(v2))
}
func contains(needle string, haystack []string) bool {
	for _, ii := range haystack {
		if needle == ii {
			return true
		}
	}
	return false
}
// transform -- transform
func transform(cf *genericclioptions.ConfigFlags, cmd *cobra.Command, args []string) error {
	var next string
	allNs, err := cmd.Flags().GetBool(commands.AllNamespacesFlag)
	if err != nil {
		allNs = false
	}
	ingressroute := args
	apply, err := cmd.Flags().GetBool(commands.ApplyFlag)
	if err != nil {
		return err
	}
	if apply {
		log.Fatal("--apply has not been implemented yet.  Stay tuned")
	}
	ns, err := cmd.Flags().GetString("namespace")
	if err != nil {
		return err
	}
	if allNs {
		ns = ""
		ingressroute = []string{}
	}
	
	klog.V(2).Infof("convert namespace=%s allNamespaces=%v", ns, allNs)
	klog.V(2).Infof("convert ingressroute=%s", ingressroute)
	klog.V(2).Infof("convert apply=%v", apply)
	for {
		listOptions := metav1.ListOptions{
			Limit:    250,
			Continue: next,
		}
		irList, err := commands.Kv1b.ContourV1beta1().IngressRoutes(ns).List(context.TODO(), listOptions)
		if err != nil {
			return fmt.Errorf("failed to construct httpproxy client: %w", err)
		}
		klog.V(2).Infof("found total %d api objects", len(irList.Items))

		for _, ir := range irList.Items {
			if len(ingressroute) > 0 && !contains(ir.Name, ingressroute) {
				klog.V(2).Infof("convert skipping %s", ir.Name)
				continue
			}
			vv, err := neatYaml(ir, false)
			if err != nil {
				return fmt.Errorf("conversion to yaml %s/%s: %w", ir.Namespace, ir.Name, err)
			}
			if klog.V(3) {
				fmt.Fprintln(os.Stderr, "# Before\n---")
				fmt.Fprintln(os.Stderr, string(vv))
			}

			hp, extra, err := translator.IngressRouteToHTTPProxy(&ir)
			if err != nil {
				fmt.Fprintf(os.Stderr, " error %s\n", err.Error())
			}

			bb, err := neatYaml(hp, true)
			if err != nil {
				return fmt.Errorf("conversion to yaml %s/%s: %w", ir.Namespace, ir.Name, err)
			}

			if klog.V(3) {
				fmt.Fprintln(os.Stderr, "# After\n---")
			}
			fmt.Fprintf(os.Stdout, "# Generated from ingressroute %s/%s\n---\n",ir.Namespace,ir.Name)
			fmt.Fprintln(os.Stdout, string(bb))
			for kk, ii := range extra {
				fmt.Fprintf(os.Stderr, "#[%d] %s\n", kk, ii)
			}
		}
		next = irList.GetContinue()
		if next == "" {
			break
		}
	}
	return nil
}
