package types

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	k8s "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// =============================================================================
// SecretsApi
// =============================================================================

type SecretsApi interface {
	Create(secret *k8s.Secret, opts meta.CreateOptions) (*k8s.Secret, error)
	Delete(name string, opts meta.DeleteOptions) error
	List(opts meta.ListOptions) (*k8s.SecretList, error)
}

type TestSecretsApi struct {
	CreateFunc func(*k8s.Secret, meta.CreateOptions) (*k8s.Secret, error)
	DeleteFunc func(string, meta.DeleteOptions) error
	ListFunc   func(meta.ListOptions) (*k8s.SecretList, error)
}

func (recv *TestSecretsApi) Create(secret *k8s.Secret, opts meta.CreateOptions) (*k8s.Secret, error) {
	return recv.CreateFunc(secret, opts)
}

func (recv *TestSecretsApi) Delete(name string, opts meta.DeleteOptions) error {
	return recv.DeleteFunc(name, opts)
}

func (recv *TestSecretsApi) List(opts meta.ListOptions) (*k8s.SecretList, error) {
	return recv.ListFunc(opts)
}

func NewTestSecretsApi(secrets map[string]*k8s.Secret, handlers ...cache.ResourceEventHandler) *TestSecretsApi {
	return &TestSecretsApi{
		CreateFunc: func(secret *k8s.Secret, opts meta.CreateOptions) (*k8s.Secret, error) {
			secrets[secret.Name] = secret
			for _, handler := range handlers {
				handler.OnAdd(secret)
			}
			return secret, nil
		},
		DeleteFunc: func(name string, opts meta.DeleteOptions) error {
			if secret, exists := secrets[name]; exists {
				delete(secrets, name)
				for _, handler := range handlers {
					handler.OnDelete(secret)
				}
			}
			return nil
		},
		ListFunc: func(opts meta.ListOptions) (list *k8s.SecretList, err error) {
			list = new(k8s.SecretList)
			for _, secret := range secrets {
				list.Items = append(list.Items, *secret)
			}
			return
		},
	}
}

// =============================================================================
// Leader
// =============================================================================

type InChargeAnswer int

const (
	Unknown InChargeAnswer = iota
	No
	Yes
)

type Leader interface {
	InCharge() InChargeAnswer
}

type TestLeader struct {
	Answer InChargeAnswer
}

func (recv *TestLeader) InCharge() InChargeAnswer {
	return recv.Answer
}

// =============================================================================
// TimeProvider
// =============================================================================

type TimeProvider interface {
	Now() time.Time
}

type TimeProviderImpl struct {
	NowFunc func() time.Time
}

func (recv *TimeProviderImpl) Now() time.Time {
	return recv.NowFunc()
}

// =============================================================================
// Bool
// =============================================================================

type Bool struct {
	bool
}

func (recv *Bool) MarshalJSON() ([]byte, error) {
	return json.Marshal(recv.bool)
}

func (recv *Bool) UnmarshalJSON(bs []byte) (err error) {
	var iface interface{}

	if err = json.Unmarshal(bs, &iface); err != nil {
		return
	}

	switch value := iface.(type) {
	case bool:
		recv.bool = value
	case string:
		var b bool
		b, err = strconv.ParseBool(value)
		if err != nil {
			return
		}
		recv.bool = b
	default:
		err = errors.New("types.Bool type was not a string or bool")
	}

	return
}

// =============================================================================
// Duration
// =============================================================================

type Duration struct {
	time.Duration
}

func (recv *Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(recv.Duration.String())
}

func (recv *Duration) UnmarshalJSON(bs []byte) (err error) {
	var iface interface{}

	if err = json.Unmarshal(bs, &iface); err != nil {
		return
	}

	switch value := iface.(type) {
	case float64:
		recv.Duration = time.Duration(value)
	case string:
		var d time.Duration
		d, err = time.ParseDuration(value)
		if err == nil {
			recv.Duration = d
		}
	default:
		err = errors.New("Duration type was not a float64 or string")
	}
	return
}

func (recv *Duration) ToProto() *duration.Duration {
	return ptypes.DurationProto(recv.Duration)
}
