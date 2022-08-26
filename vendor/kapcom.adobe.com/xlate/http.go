package xlate

type (
	CRDLists struct {
		Ingresses []string `json:"ingresses"`
		Endpoints []string `json:"endpoints"`
		Services  []string `json:"services"`
	}

	SotWResponse struct {
		Namespaces map[string]CRDLists `json:"namespaces"`
		CDSSotW    []string            `json:"cds"`
		EDSSotW    []string            `json:"eds"`
		LDSSotW    []string            `json:"lds"`
		RDSSotW    []string            `json:"rds"`
		SDSSotW    []string            `json:"sds"`
	}
)
