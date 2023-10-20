package xlate

import (
	"encoding/json"
	"path"
)

// Delegate is a delegate in a route
// +k8s:deepcopy-gen=true
type Delegate struct {
	Name      string
	Namespace string
	Status    string

	Inherit        bool
	Prefix         string // Prefix match
	HeaderMatchers []HeaderMatcher
}

func (d *Delegate) HasConditions() bool {
	return d.Prefix != "" || len(d.HeaderMatchers) > 0
}

///////////////////////////////////////////////////////////

// DelegatesChainNode is a node in a delegates chain
// +k8s:deepcopy-gen=true
type DelegatesChainNode *Delegate

// DelegatesChain is a chain of delegates
// +k8s:deepcopy-gen=true
type DelegatesChain []DelegatesChainNode

// GetHeadersMatchers returns the list of headers matchers
func (dc DelegatesChain) GetHeadersMatchers() []HeaderMatcher {
	res := []HeaderMatcher{}
	for _, node := range dc {
		res = append(res, node.HeaderMatchers...)
	}
	return res
}

// GetPrefix returns the complete prefix of the delegates chain
func (dc DelegatesChain) GetPrefix() string {
	res := ""
	for _, node := range dc {
		res = path.Join(res, node.Prefix)
	}
	return res
}

// Empty returns true if the chain is empty
func (dc DelegatesChain) Empty() bool {
	return len(dc) == 0
}

// Equal compares two delegates chains
func (dc DelegatesChain) Equal(other DelegatesChain) bool {
	if len(dc) != len(other) {
		return false
	}
	for i := range dc {
		if dc[i] != other[i] {
			return false
		}
	}
	return true
}

// Append appends a new delegate to the chain
func (dc *DelegatesChain) Append(node DelegatesChainNode) {
	if node.Inherit {
		*dc = append(*dc, node)
	}
}

// Root returns the root node of the chain
func (dc DelegatesChain) Root() *DelegatesChainNode {
	if len(dc) > 0 {
		return &dc[0]
	}
	return nil
}

// Inherits returns true if the chain inherits properties
func (dc DelegatesChain) Inherits() bool {
	r := dc.Root()
	if r != nil {
		return (*r).Inherit
	}
	return false
}

///////////////////////////////////////////////////////////

// DelegatesChains is a map of delegates chains by ingress
type DelegatesChains map[*Ingress][]DelegatesChain

func (d DelegatesChains) From(ingress *Ingress) []DelegatesChain {
	return d[ingress]
}

func (d DelegatesChains) MarshalJSON() ([]byte, error) {
	// convert the map to a map[string][]DelegatesChain for making things easier for the json encoder
	data := make(map[string][]DelegatesChain, len(d))
	for ingress, chain := range d {
		data[ingress.Name] = chain
	}
	return json.Marshal(data)
}

func (d DelegatesChains) UnmarshalJSON(data []byte) error {
	// not implemented
	return nil
}
