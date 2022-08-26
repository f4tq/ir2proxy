package set

import (
	"errors"
	"reflect"
)

type Set map[string]interface{}

func New() Set {
	return make(Set)
}

func Difference(a Set, b Set) Set {
	c := make(Set)

	for ak, av := range a {
		if _, exists := b[ak]; !exists {
			c[ak] = av
		}
	}

	return c
}

func Differences(a Set, b Set) bool {
	for ak := range a {
		if _, exists := b[ak]; !exists {
			return true
		}
	}

	return false
}

func Intersection(a Set, b Set) Set {
	c := make(Set)

	for ak, av := range a {
		if _, exists := b[ak]; exists {
			c[ak] = av
		}
	}

	return c
}

func Intersects(a Set, b Set) bool {
	for ak := range a {
		if _, exists := b[ak]; exists {
			return true
		}
	}

	return false
}

func IntersectionEquality(a Set, b Set) (Set, error) {
	c := make(Set)

	for ak, av := range a {
		if bv, exists := b[ak]; exists {
			if !reflect.DeepEqual(av, bv) {
				return nil, errors.New("value inequality for " + ak)
			}
			c[ak] = av
		}
	}

	return c, nil
}

func Union(a Set, b Set) Set {
	c := make(Set)

	for k, v := range a {
		c[k] = v
	}

	for k, v := range b {
		c[k] = v
	}

	return c
}

func UnionEquality(a Set, b Set) (Set, error) {
	c := make(Set)

	for k, v := range a {
		if v2, exists := b[k]; exists && !reflect.DeepEqual(v, v2) {
			return nil, errors.New("value inequality for " + k)
		}
		c[k] = v
	}

	for k, v := range b {
		c[k] = v
	}

	return c, nil
}
