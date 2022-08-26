package xlate

import (
	"kapcom.adobe.com/constants/annotations"
	crds "kapcom.adobe.com/crds/v1"

	"gopkg.in/inconshreveable/log15.v2"
	k8s "k8s.io/api/core/v1"
)

type (
	ingressMap map[string]**Ingress

	namespaceCRDs struct {
		ingressTypes map[string]ingressMap
		endpoints    map[string]*k8s.Endpoints
		services     map[string]*k8s.Service
		sidecars     map[string]*crds.Sidecar

		// A map of Delegate name to list of stable pointers (see below) of
		// Ingresses that failed delegation because the Delegate was not yet
		// synced
		failedDelegations map[string][]**Ingress
	}
)

func endpointsIPs(kEndpoints *k8s.Endpoints) (ips []string) {
	if kEndpoints == nil {
		return
	}

	for _, subset := range kEndpoints.Subsets {
		for _, address := range subset.Addresses {
			if address.IP != "" {
				ips = append(ips, address.IP)
			} else if address.Hostname != "" {
				ips = append(ips, address.Hostname)
			}
		}
	}
	return
}

func newNamespaceCRDs() namespaceCRDs {
	return namespaceCRDs{
		ingressTypes: make(map[string]ingressMap),
		endpoints:    make(map[string]*k8s.Endpoints),
		services:     make(map[string]*k8s.Service),
		sidecars:     make(map[string]*crds.Sidecar),

		failedDelegations: make(map[string][]**Ingress),
	}
}

func (recv namespaceCRDs) addIngress(log log15.Logger, lc *ListenerConfig, ingress *Ingress) (success bool) {
	if _, exists := lc.IngressClasses[ingress.Class]; !exists {
		return
	}

	log.Info("add/update Ingress",
		"ns", ingress.Namespace, "name", ingress.Name,
		"type", ingress.TypeURL, annotations.IC, ingress.Class,
		"fqdn", ingress.Fqdn)

	var iMap ingressMap
	if iMap = recv.ingressTypes[ingress.TypeURL]; iMap == nil {
		iMap = make(ingressMap)
		recv.ingressTypes[ingress.TypeURL] = iMap
	}

	var iPtr **Ingress
	if iPtr = iMap[ingress.Name]; iPtr == nil {
		iPtr = new(*Ingress)
		iMap[ingress.Name] = iPtr
	}

	*iPtr = ingress

	success = true
	return
}

func (recv namespaceCRDs) getIngressPtr(ingress *Ingress) (iPtr **Ingress) {
	iMap := recv.ingressTypes[ingress.TypeURL]
	if iMap == nil {
		return
	}

	iPtr = iMap[ingress.Name]
	return
}

func (recv namespaceCRDs) deleteIngress(log log15.Logger, ingress *Ingress) {
	log.Info("delete Ingress",
		"ns", ingress.Namespace, "name", ingress.Name,
		"type", ingress.TypeURL, annotations.IC, ingress.Class)

	iMap := recv.ingressTypes[ingress.TypeURL]
	delete(iMap, ingress.Name) // delete on a nil map does not panic
}

func (recv namespaceCRDs) addService(log log15.Logger, kService *k8s.Service) {
	log.Info("add/update Service", "ns", kService.Namespace, "name", kService.Name)
	recv.services[kService.Name] = kService
}

func (recv namespaceCRDs) deleteService(log log15.Logger, kService *k8s.Service) {
	log.Info("delete Service", "ns", kService.Namespace, "name", kService.Name)
	delete(recv.services, kService.Name)
}

func (recv namespaceCRDs) addEndpoints(log log15.Logger, kEndpoints *k8s.Endpoints) {
	log.Info("add/update Endpoints", "ns", kEndpoints.Namespace, "name", kEndpoints.Name,
		"ips", endpointsIPs(kEndpoints))
	recv.endpoints[kEndpoints.Name] = kEndpoints
}

func (recv namespaceCRDs) deleteEndpoints(log log15.Logger, kEndpoints *k8s.Endpoints) {
	log.Info("delete Endpoints", "ns", kEndpoints.Namespace, "name", kEndpoints.Name,
		"ips", endpointsIPs(kEndpoints))
	delete(recv.endpoints, kEndpoints.Name)
}

func (recv namespaceCRDs) addSidecar(log log15.Logger, sc *crds.Sidecar) {
	log.Info("add/update Sidecar", "ns", sc.Namespace, "name", sc.Name)
	recv.sidecars[sc.Name] = sc
}

func (recv namespaceCRDs) deleteSidecar(log log15.Logger, sc *crds.Sidecar) {
	log.Info("delete Sidecar", "ns", sc.Namespace, "name", sc.Name)
	delete(recv.sidecars, sc.Name)
}

// given a Delegate in this namespace, add the stable pointer of the Delegator
// (possibly from another namespace)
func (recv namespaceCRDs) addFailedDelegation(log log15.Logger, delegate string, iPtr **Ingress) {
	if iPtr == nil {
		log.Error("iPtr == nil")
		return
	}

	if _, exists := recv.failedDelegations[delegate]; !exists {
		recv.failedDelegations[delegate] = []**Ingress{}
	}

	var referenced bool
	for _, iPtr2 := range recv.failedDelegations[delegate] {
		if iPtr == iPtr2 {
			referenced = true
			break
		}
	}

	if !referenced {
		recv.failedDelegations[delegate] = append(recv.failedDelegations[delegate], iPtr)
		log.Info("added failed delegation", "delegate", delegate,
			"delegator_ns", (*iPtr).Namespace, "delegator_name", (*iPtr).Name)
	}
}

// given a Delegate in this namespace, delete the stable pointer of the Delegator
// (possibly from another namespace)
func (recv namespaceCRDs) deleteFailedDelegation(log log15.Logger, delegate string, iPtr **Ingress) {
	if iPtr == nil {
		log.Error("iPtr == nil")
		return
	}

	var (
		foundIngress bool
		i            int
		iPtr2        **Ingress
	)

	iPtrList := recv.failedDelegations[delegate]
	for i, iPtr2 = range iPtrList {
		if iPtr == iPtr2 {
			foundIngress = true
			break
		}
	}

	if foundIngress {
		iPtrList = append(iPtrList[:i], iPtrList[i+1:]...)
		if len(iPtrList) > 0 {
			recv.failedDelegations[delegate] = iPtrList
		} else {
			delete(recv.failedDelegations, delegate)
		}
		log.Info("deleted failed delegation", "delegate", delegate,
			"delegator_ns", (*iPtr).Namespace, "delegator_name", (*iPtr).Name)
	}
}
