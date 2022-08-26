package show

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	kapcomv1 "kapcom.adobe.com/contour/generated/v1/clientset/versioned"
	kapcomv1beta "kapcom.adobe.com/contour/generated/v1beta/clientset/versioned"

	"github.com/spf13/cobra"
	"github.com/tidwall/sjson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // combined authprovider import
	"k8s.io/klog"
	"sigs.k8s.io/yaml"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands/util"
	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands"

)
var (
	cf *genericclioptions.ConfigFlags
)

func CreateShowRootCommand(flags *genericclioptions.ConfigFlags) *cobra.Command {

	var rootCmd2 = &cobra.Command{
		Use:          "kubectl-kapcom",
		SilenceUsage: true, // for when RunE returns an error
		Short:        "kapcom ",
		Example:      "kubectl kapcom my_ingress_route_name\n",
		Args:         cobra.MinimumNArgs(0),
		RunE:         func(cmd *cobra.Command, args []string) error {
			util.PrintError(run(flags,cmd,args))
			return nil
       },
		//	Version:      versionString(),
	}

	return rootCmd2
}
func run(cf *genericclioptions.ConfigFlags, command *cobra.Command, args []string) error {
	var next string
	allNs, err := command.Flags().GetBool(commands.AllNamespacesFlag)
	if err != nil {
		allNs = false
	}

	restConfig, err := cf.ToRESTConfig()
	if err != nil {
		return err
	}
	restConfig.QPS = 1000
	restConfig.Burst = 1000

	kv1b, err := kapcomv1beta.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to construct ingressroute client: %w", err)
	}

	_, err = kapcomv1.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to construct httpproxy client: %w", err)
	}
	ns := util.GetNamespace(cf)
	if allNs {
		ns = ""
	}
	klog.V(2).Infof("namespace=%s allNamespaces=%v", ns, allNs)
	for {
		irList, err := kv1b.ContourV1beta1().IngressRoutes(ns).List(context.TODO(), metav1.ListOptions{
			Limit:    250,
			Continue: next,
		})
		if err != nil {
			return fmt.Errorf("failed to construct httpproxy client: %w", err)
		}
		klog.V(2).Infof("found total %d api objects", len(irList.Items))
		for _, v := range irList.Items {
			vraw, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("failed to construct httpproxy client: %w", err)
			}
			v2 := string(vraw)
			for _, item := range commands.Neat {

				vint, err := sjson.Delete(v2, item)
				if err != nil {
					return fmt.Errorf("failed to delete path %s: %w", item, err)
				}
				v2 = vint
			}
			vv, err := yaml.JSONToYAML([]byte(v2))
			if err != nil {
				return fmt.Errorf("conversion to yaml %s/%s: %w", v.Namespace, v.Name, err)
			}
			fmt.Fprintln(os.Stderr, string(vv))
		}
		next = irList.GetContinue()
		if next == "" {
			break
		}
	}
	return nil
}
