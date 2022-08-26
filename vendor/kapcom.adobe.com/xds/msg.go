package xds

import (
	"kapcom.adobe.com/set"
)

type (
	shutdownMsg struct{}

	stateChangeMsg struct {
		subset    EnvoySubset
		typeUrl   TypeURL
		resources set.Set
	}

	internalDDRMsg struct {
		typeUrl TypeURL
	}

	envoyConnDestroyedMsg struct {
		conn *envoyConnection
	}

	envoyConnCreatedMsg struct {
		conn *envoyConnection
	}

	envoyConnIdentifiedMsg struct {
		conn         *envoyConnection
		continueChan chan struct{}
	}
)
