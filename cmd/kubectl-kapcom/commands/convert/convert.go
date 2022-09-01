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
	v1 "kapcom.adobe.com/contour/v1"

	"github.com/spf13/cobra"
	_ "github.com/spf13/viper"
	"github.com/tidwall/sjson"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // combined authprovider import
	"k8s.io/klog"
	"sigs.k8s.io/yaml"
)

// CreateConvertCommand creates and returns this cobra subcommand
func CreateConvertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ir2proxy",
		Short: "ir2proxy transforms ingressroute into httpproxy",
		Example: `
		#
		kubectl kapcom ir2proxy -A
		kubectl kapcom ir2proxy -n monitoring grafana`,
		RunE: func(cmd *cobra.Command, args []string) error {
			util.PrintError(transform( cmd, args))
			return nil
		},
	}
	util.AddNamespacesFlag(cmd)
	cmd.Flags().Bool(commands.ApplyFlag, false, "Transform all ingressroutes to httpproxy in place")
	cmd.Flags().StringP("namespace", "n", "default", "namespace")
	cmd.Flags().Int16P(commands.Priority, "p", 2, "set annotation kapcom.adobe.io/priority: $priority")
	cmd.Flags().Bool(commands.Force, false, "force --apply to go forward despite warnings.  BEWARE")

	return cmd
}

type Extra func(vin string) (string, error)

// neatYaml -- helper that removes kubernetes injected keys from given object's yaml rep
func neatYaml(ir interface{}, _ bool, handlers ...Extra) ([]byte, error) {
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
	for kk, vv := range handlers {
		vint, err := vv(v2)
		if err != nil {
			return nil, fmt.Errorf("failed on function[%d] handler because %s", kk, err)
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
func transform( cmd *cobra.Command, args []string) error {
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
	force, err := cmd.Flags().GetBool(commands.Force)
	if err != nil {
		return err
	}
	ns, err := cmd.Flags().GetString("namespace")
	if err != nil {
		return err
	}
	priority, err := cmd.Flags().GetInt16(commands.Priority)
	if err != nil {
		return err
	}
	if allNs {
		ns = ""
		ingressroute = []string{}
	} else if ns == "" {
		ns = "default"
		log.Fatal("No namespace designated.  Please be explicit")
	}

	if apply && allNs {
		log.Fatal("--apply is restricted to maximum of namespace scope blast radius by policy")
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
				fmt.Fprintf(os.Stderr, "%s/%s error %s\n", ir.Namespace, ir.Name, err.Error())
				continue
			}
			hp.Annotations[commands.AnnotationPriorityKey] = fmt.Sprintf("%d", priority)
			if apply {
				if len(extra) > 0 && !force {
					fmt.Fprintf(os.Stderr, "IngressRoute %s/%s refusing to --apply due to warnings:\n", ir.Namespace, ir.Name)
					for kk, ii := range extra {
						fmt.Fprintf(os.Stderr, "#[%d] %s\n", kk, ii)
					}
					continue
				}
				doApply(hp)
			}
			bb, err := neatYaml(hp, true, func(vv string) (string, error) {
				// clean up emitted yaml
				if hp.Spec.TCPProxy != nil && hp.Spec.TCPProxy.LeastRequestLbConfig == nil {
					vint, err := sjson.Delete(vv, "spec.tcpproxy.adobe\\:leastRequestLbConfig")
					if err != nil {
						return "", fmt.Errorf("error deleting spec.tcpproxy.adobe\\:leastRequestLbConfig")
					}
					vv = vint
				}
				for kk, rr := range hp.Spec.Routes {
					// filter out LeastRequestLbConfig from dumping if nil
					if rr.LeastRequestLbConfig == nil {
						vint, err := sjson.Delete(vv, fmt.Sprintf("spec.routes.%d.adobe\\:leastRequestLbConfig", kk))
						if err != nil {
							return "", fmt.Errorf("error deleting loadbalancerpolicy %d", kk)
						}
						vv = vint
					}
					// filter out idleTimeout
					if rr.TimeoutPolicy != nil {
						if rr.TimeoutPolicy.Idle == "" {
							vint, err := sjson.Delete(vv, fmt.Sprintf("spec.routes.%d.timeoutPolicy.idle", kk))
							if err != nil {
								return "", fmt.Errorf("error deleting route.timeoutPolicy.idle %d", kk)
							}
							vv = vint
						}
						if rr.TimeoutPolicy.Response== "" {
							vint, err := sjson.Delete(vv, fmt.Sprintf("spec.routes.%d.timeoutPolicy.response", kk))
							if err != nil {
								return "", fmt.Errorf("error deleting route.timeoutPolicy.response %d", kk)
							}
							vv = vint
						}
					}
				}
				return vv, nil
			})
			if err != nil {
				return fmt.Errorf("conversion to yaml %s/%s: %w", ir.Namespace, ir.Name, err)
			}

			if klog.V(3) {
				fmt.Fprintln(os.Stderr, "# After\n---")
			}
			fmt.Fprintf(os.Stdout, "# Generated from ingressroute %s/%s\n---\n", ir.Namespace, ir.Name)
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

func doApply(converted *v1.HTTPProxy) (_ *v1.HTTPProxy, err error) {

	client := commands.Kv1.ProjectcontourV1().HTTPProxies(converted.Namespace)
	_, err = client.Get(context.Background(), converted.Name, metav1.GetOptions{})

	if err != nil && apierrors.IsNotFound(err) {
		return client.Create(context.Background(), converted, metav1.CreateOptions{
			TypeMeta:     metav1.TypeMeta{},
			DryRun:       nil,
			FieldManager: "",
		})
	}
	return nil, err
}
