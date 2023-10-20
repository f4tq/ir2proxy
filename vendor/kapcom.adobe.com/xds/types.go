package xds

import (
	"kapcom.adobe.com/set"
)

type (
	RouteConfigurationMeta struct {
		Class           string
		ClustersWarming set.Set
	}
)
