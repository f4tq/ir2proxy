package config

import (
	"fmt"
	"strings"
)

const (
	None = iota
	External
	Internal
)

type CertManagement int

func (recv *CertManagement) String() string {
	switch *recv {
	case None:
		return "none"
	case External:
		return "external"
	case Internal:
		return "internal"
	}
	return "unknown"
}

// UnmarshalFlag -- take an rep of truth
func (recv *CertManagement) UnmarshalFlag(value string) error {
	switch strings.ToUpper(value) {
	case "INTERNAL", "KAPCOM":
		*recv = Internal
	case "EXTERNAL":
		*recv = External
	default:
		*recv = None
	}
	return nil
}

// MarshalFlag -- emit string value of current truth
func (recv *CertManagement) MarshalFlag() (string, error) {
	v := recv.String()
	if v == "unknown" {
		return "", fmt.Errorf("unknown mtls type %d", recv)
	}
	return v, nil
}
func (recv *CertManagement) Value() int {
	return int(*recv)
}
