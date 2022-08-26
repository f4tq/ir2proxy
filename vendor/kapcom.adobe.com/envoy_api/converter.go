package envoy_api

import (
	"errors"
)

type FilterMarshaller interface {
	Type() string
	Unmarshal(bb []byte) (interface{}, error)
	Marshal(interface{}) ([]byte, error)
	String() string
	Compare(interface{}, interface{}) error
}

var (
	filterTypeConverter map[string]FilterMarshaller = make(map[string]FilterMarshaller)
)

func RegisterFilterConverter(converter FilterMarshaller) error {
	if _, ok := filterTypeConverter[converter.Type()]; ok {
		return errors.New("already registered")
	}
	filterTypeConverter[converter.Type()] = converter
	return nil
}
func Unregister(converter FilterMarshaller) error {
	if _, ok := filterTypeConverter[converter.Type()]; ok {
		delete(filterTypeConverter, converter.Type())
		return nil
	}
	return errors.New("no such converter")
}
