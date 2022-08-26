package xds

import (
	"kapcom.adobe.com/set"
)

type (
	RouteConfigurationMeta struct {
		Clusters        set.Set
		ClustersWarming set.Set
	}
)
