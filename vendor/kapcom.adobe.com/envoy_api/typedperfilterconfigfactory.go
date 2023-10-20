package envoy_api

import (
	"encoding/json"
	"errors"
	"fmt"

	"kapcom.adobe.com/config"

	"github.com/davecgh/go-spew/spew"
)

/*
		Register & manage envoy TypedPerFilterConfig instances
		Handles
		- Many are proto based with oneof members (poly typed)
	    - Allows specific overrides (user defined types) for otherwise native Struct_* types
		- Maintains and project inteface for handling specific, user defined types including complex types such as Ratelimit, or ExtAuthz

		If a given type has no type conversion registered, a map[string]*json.RawMessage is returned and can be retrieved by perfilter key
*/
type (
	FilterCreator               func() (interface{}, error)
	TypedPerFilterConfigFactory struct {
		instances map[string]interface{}
	}
)

var (
	perFilterRegistry map[string]FilterCreator = make(map[string]FilterCreator)
)

func init() {
	perFilterRegistry["envoy.filters.http.header_size"] = func() (interface{}, error) { return &EnvoyFiltersHTTPHeaderSize{}, nil }
	perFilterRegistry["envoy.filters.http.ip_allow_deny"] = func() (interface{}, error) { return &EnvoyFiltersHTTPIpAllowDeny{}, nil }
}
func RegisterPerFilterCreator(id string, creator FilterCreator) {
	perFilterRegistry[id] = creator
}

func (a TypedPerFilterConfigFactory) Compare(b TypedPerFilterConfigFactory) error {
	return nil
}
func (us *TypedPerFilterConfigFactory) Lookup(desc string) (interface{}, error) {
	if us.instances != nil {
		item, ok := us.instances[desc]
		if ok {
			return item, nil
		}
	}
	return nil, fmt.Errorf("%s not found", desc)
}
func (us *TypedPerFilterConfigFactory) GetHttpExtAuthz() (*HttpExtAuthz, error) {
	if us.instances != nil {
		item, ok := us.instances["envoy.filters.http.ext_authz"]
		if ok {
			tt, ok := item.(*HttpExtAuthz)
			if ok {
				return tt, nil
			}
		}
	}
	return nil, errors.New("no instance envoy.filters.http.ext_authz")
}

func (us *TypedPerFilterConfigFactory) GetEnvoyFiltersHTTPIpAllowDeny() (*EnvoyFiltersHTTPIpAllowDeny, error) {
	if us.instances != nil {
		item, ok := us.instances["envoy.filters.http.ip_allow_deny"]
		if ok {
			tt, ok := item.(*EnvoyFiltersHTTPIpAllowDeny)
			if ok {
				return tt, nil
			}
		}
	}
	return nil, errors.New("no instance envoy.filters.http.ip_allow_deny")
}
func (us *TypedPerFilterConfigFactory) GetEnvoyFiltersHTTPHeaderSize() (*EnvoyFiltersHTTPHeaderSize, error) {
	if us.instances != nil {
		item, ok := us.instances["envoy.filters.http.header_size"]
		if ok {
			tt, ok := item.(*EnvoyFiltersHTTPHeaderSize)
			if ok {
				return tt, nil
			}
		}
	}
	return nil, errors.New("no instance envoy.filters.http.header_size")
}

func (us *TypedPerFilterConfigFactory) MarshalJSON() ([]byte, error) {
	if us.instances == nil || len(us.instances) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(us.instances)
}

// Expects Perfilter configs (value is a list)
func (us *TypedPerFilterConfigFactory) UnmarshalJSON(bb []byte) error {
	if us.instances == nil {
		us.instances = make(map[string]interface{})
	}
	tmp := make(map[string]*json.RawMessage)
	err := json.Unmarshal(bb, &tmp)
	if err != nil {
		config.Log.Debug(fmt.Sprintf("TypedPerFilterConfig.unmarshal tmp failed due to %s >>%s<<", err.Error(), string(bb)))
		return fmt.Errorf(".TypedPerFilter failed %s", err.Error())
	}
	if len(tmp) == 0 {
		config.Log.Debug(".TypedPerFilterConfig - No elements in")
		return errors.New(".TypedPerFilterConfig - No elements in")
	}
	for k, v := range tmp {
		config.Log.Debug(fmt.Sprintf("TypedPerFilterConfig key %s . - %s", k, string(*v)))
		// there was no specific @type to try so fall back
		creator, ok := perFilterRegistry[k]
		if ok {
			inst, err := creator()
			if err == nil {
				err = json.Unmarshal(*v, inst)
				if err == nil {
					us.instances[k] = inst
					config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig %s instance created %T", k, inst))
					continue
				}
			}
			config.Log.Debug(fmt.Sprintf("TypedPerFilterConfig key %s  failed because %s", k, err))
		}
		// otherwise, try harder
		// sanitize the raw block
		tt := make(map[string]interface{})
		err = json.Unmarshal([]byte(*v), &tt)
		if err != nil {
			//return fmt.Errorf(".TypedPerFilterConfig %s not map structured: %s", k, err)
			config.Log.Error(fmt.Sprintf(".TypedPerFilterConfig %s not map structured: %s", k, err))
			continue
		}
		// See if there is an @type and a registered decoder for i
		type_creator, ok := tt["@type"]
		if !ok {
			// oh well, save the map
			us.instances[k] = v
			continue
		}
		var bb []byte
		delete(tt, "@type")

		value, ok := tt["value"]
		// clean up the rep for re-decoding
		if ok {
			// actual type value to decode stored under key value
			delete(tt, "value")
			// value is the target
			bb, err = json.Marshal(value)
			if err != nil {
				us.instances[k] = v
				continue
			}
		} else {
			bb, err = json.Marshal(tt)
			if err != nil {
				config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig  marshalling temp map? %s - %s", k, err))
				us.instances[k] = v
				continue
			}
		}
		// try the main value again
		if type_creator != nil {
			// first try a registered @type converter
			creator, ok = perFilterRegistry[type_creator.(string)]
			if ok {
				inst, err := creator()
				if err == nil {
					config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig %s %T w/modified bb %s", k, inst, spew.Sdump(bb)))
					err = json.Unmarshal(bb, inst)
					if err == nil {
						us.instances[k] = inst
						config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig %s instance created using @type(%s) %T", k, type_creator.(string), inst))
						continue
					}
				}
			}
		}
		// @type's removed from value.  just in case it was interferring with the base case
		creator, ok = perFilterRegistry[k]
		if ok {
			inst, err := creator()
			if err == nil {
				err = json.Unmarshal(bb, inst)
				if err == nil {
					us.instances[k] = inst
					config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig %s instance created %T trying harder", k, inst))
					continue
				}
			}
		}
		config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig %s  no registered @type create  %s", k, type_creator.(string)))

		// whoa, still here, save the key->json.RawMesage
		us.instances[k] = v
	}
	config.Log.Debug(fmt.Sprintf(".TypedPerFilterConfig success.  dumping self %s", spew.Sdump(us)))
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (us *TypedPerFilterConfigFactory) DeepCopyInto(out *TypedPerFilterConfigFactory) {
	us.instances = make(map[string]interface{})
	bb, err := out.MarshalJSON()

	if err != nil {
		config.Log.Error(fmt.Sprintf(".TypedPerFilterConfig DeepCopyInto error %s", err))
		return
	}
	err = us.UnmarshalJSON(bb)
	if err != nil {
		config.Log.Error(fmt.Sprintf(".TypedPerFilterConfig DeepCopyInto error %s", err))
		return
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PerFilterConfig.
func (us *TypedPerFilterConfigFactory) DeepCopy() *TypedPerFilterConfigFactory {
	if us == nil {
		return nil
	}
	out := new(TypedPerFilterConfigFactory)
	us.DeepCopyInto(out)
	return out
}
