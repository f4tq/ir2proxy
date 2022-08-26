package ciphers

var (
	curatedCiphers      map[string]struct{}
	defaultCipherSuites []string

	// intialize once since it'll be re-used many times
	curatedCipherList []string
)

func init() {
	curatedCiphers = map[string]struct{}{
		"ECDHE-ECDSA-AES128-GCM-SHA256": {},
		"ECDHE-ECDSA-CHACHA20-POLY1305": {},
		"ECDHE-ECDSA-AES128-SHA":        {},
		"ECDHE-ECDSA-AES256-GCM-SHA384": {},
		"ECDHE-ECDSA-AES256-SHA":        {},

		"ECDHE-RSA-AES128-GCM-SHA256": {},
		"ECDHE-RSA-CHACHA20-POLY1305": {},
		"ECDHE-RSA-AES128-SHA":        {},
		"ECDHE-RSA-AES256-GCM-SHA384": {},
		"ECDHE-RSA-AES256-SHA":        {},

		// add additional ciphers below
		"TLS_RSA_WITH_AES_128_CBC_SHA":    {},
		"TLS_RSA_WITH_AES_128_GCM_SHA256": {},
		"TLS_RSA_WITH_AES_256_CBC_SHA":    {},
		"TLS_RSA_WITH_AES_256_GCM_SHA384": {},
	}

	defaultCipherSuites = []string{
		"[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305]",
		"[ECDHE-RSA-AES128-GCM-SHA256|ECDHE-RSA-CHACHA20-POLY1305]",
		"ECDHE-ECDSA-AES128-SHA",
		"ECDHE-RSA-AES128-SHA",
		"ECDHE-ECDSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-ECDSA-AES256-SHA",
		"ECDHE-RSA-AES256-SHA",
	}

	for c := range curatedCiphers {
		curatedCipherList = append(curatedCipherList, c)
	}
}

func CuratedCiphers() []string {
	return curatedCipherList
}

func DefaultCipherSuites() []string {
	return defaultCipherSuites
}

func IsCurated(cipher string) bool {
	_, ok := curatedCiphers[cipher]
	return ok
}
