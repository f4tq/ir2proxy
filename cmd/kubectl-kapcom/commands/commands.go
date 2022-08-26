package commands
import (
	kapcomv1 "kapcom.adobe.com/contour/generated/v1/clientset/versioned"
	kapcomv1beta "kapcom.adobe.com/contour/generated/v1beta/clientset/versioned"

)
const (
	AllNamespacesFlag = "all-namespaces"
	IngressrouteFlag  = "ingressroute"
	HttpProxyFlag = "httpproxy"
	ApplyFlag         = "apply"
	PodFlag = "pod"
	DeploymentFlag = "deployment"
	SelectorFlag = "selector"
)

var (
	Neat    = []string{"spec.objectmeta",
	"spec.uid",
	"spec.resourceversion",
	"metadata.creationTimestamp",
	"metadata.managedFields",
	"metadata.resourceVersion",
	"metadata.generation",
	"metadata.annotations.kubectl\\.kubernetes\\.io\\/last\\-applied\\-configuration",
	"metadata.uid",
	"status"}

	Kv1 *kapcomv1.Clientset
	Kv1b *kapcomv1beta.Clientset
)