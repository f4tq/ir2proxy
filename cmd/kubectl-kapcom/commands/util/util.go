package util

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/projectcontour/ir2proxy/cmd/kubectl-kapcom/commands"
	"github.com/spf13/cobra"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// The default deployment and service names for envoy
const (
	DefaultEnvoyDeploymentName = "envoy"
	DefaultEnvoyServiceName    = "envoy-stats"
)

// IssuePrefix is the github url that we can append an issue number to to link to it
const IssuePrefix = "https://git.core.adobe.com/adobe-platform/kapcom/issues/"

var versionRegex = regexp.MustCompile(`(\d)+\.(\d)+\.(\d)+.*`)

// PrintError receives an error value and prints it if it exists
func PrintError(e error) {
	if e != nil {
		fmt.Println(e)
	}
}

// ParseVersionString returns the major, minor, and patch numbers of a version string
func ParseVersionString(v string) (int, int, int, error) {
	parts := versionRegex.FindStringSubmatch(v)

	if len(parts) != 4 {
		return 0, 0, 0, fmt.Errorf("could not parse %v as a version string (like 0.20.3)", v)
	}

	major, _ := strconv.Atoi(parts[1])
	minor, _ := strconv.Atoi(parts[2])
	patch, _ := strconv.Atoi(parts[3])

	return major, minor, patch, nil
}

// InVersionRangeInclusive checks that the middle version is between the other two versions
func InVersionRangeInclusive(start, v, stop string) bool {
	return !isVersionLessThan(v, start) && !isVersionLessThan(stop, v)
}

func isVersionLessThan(a, b string) bool {
	aMajor, aMinor, aPatch, err := ParseVersionString(a)
	if err != nil {
		panic(err)
	}

	bMajor, bMinor, bPatch, err := ParseVersionString(b)
	if err != nil {
		panic(err)
	}

	if aMajor != bMajor {
		return aMajor < bMajor
	}

	if aMinor != bMinor {
		return aMinor < bMinor
	}

	return aPatch < bPatch
}

// AddNamespacesFlag adds  --ingressroute flag to a cobra command
func AddNamespacesFlag(cmd *cobra.Command) *bool {
	v := false
	cmd.Flags().BoolVarP(&v,commands.AllNamespacesFlag,"A", false, "query all objects in all API groups, both namespaced and non-namespaced")
	return &v
}

// AddIngressrouteFlag adds a --ingressroute flag to a cobra command
func AddIngressrouteFlag(cmd *cobra.Command) *string {
	v := ""
	cmd.Flags().StringVarP(&v, commands.IngressrouteFlag, "i","", "Ingressroute name ")
	return &v
}
// AddHttpProxyFlag adds a --httpproxy flag to a cobra command
func AddHttpProxyFlag(cmd *cobra.Command) *string {
	v := ""
	cmd.Flags().StringVarP(&v, commands.HttpProxyFlag, "h", "", "HttpProxy name")
	return &v
}

// AddPodFlag adds a --pod flag to a cobra command
func AddPodFlag(cmd *cobra.Command) *string {
	v := ""
	cmd.Flags().StringVar(&v, commands.PodFlag, "", "Target a particular pod")
	return &v
}

// AddSelectorFlag adds a --selector flag to a cobra command
func AddSelectorFlag(cmd *cobra.Command) *string {
	v := ""
	cmd.Flags().StringVarP(&v, commands.SelectorFlag, "l", "", "Selector (label query) of envoy pod")
	return &v
}

// GetNamespace takes a set of kubectl flag values and returns the namespace we should be operating in
func GetNamespace(flags *genericclioptions.ConfigFlags) string {
	namespace, _, err := flags.ToRawKubeConfigLoader().Namespace()
	if err != nil || len(namespace) == 0 {
		namespace = apiv1.NamespaceDefault
	}
	return namespace
}

