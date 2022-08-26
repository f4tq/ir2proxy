// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package xlate

import (
	time "time"

	envoyapi "kapcom.adobe.com/envoy_api"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Cidr) DeepCopyInto(out *Cidr) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Cidr.
func (in *Cidr) DeepCopy() *Cidr {
	if in == nil {
		return nil
	}
	out := new(Cidr)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Cluster) DeepCopyInto(out *Cluster) {
	*out = *in
	if in.Weight != nil {
		in, out := &in.Weight, &out.Weight
		*out = new(uint32)
		**out = **in
	}
	if in.LeastRequestLbConfig != nil {
		in, out := &in.LeastRequestLbConfig, &out.LeastRequestLbConfig
		*out = new(LeastRequestLbConfig)
		**out = **in
	}
	if in.HealthCheck != nil {
		in, out := &in.HealthCheck, &out.HealthCheck
		*out = new(HealthCheck)
		**out = **in
	}
	if in.EndpointCircuitBreaker != nil {
		in, out := &in.EndpointCircuitBreaker, &out.EndpointCircuitBreaker
		*out = new(EndpointCircuitBreaker)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Cluster.
func (in *Cluster) DeepCopy() *Cluster {
	if in == nil {
		return nil
	}
	out := new(Cluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Delegate) DeepCopyInto(out *Delegate) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Delegate.
func (in *Delegate) DeepCopy() *Delegate {
	if in == nil {
		return nil
	}
	out := new(Delegate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointCircuitBreaker) DeepCopyInto(out *EndpointCircuitBreaker) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointCircuitBreaker.
func (in *EndpointCircuitBreaker) DeepCopy() *EndpointCircuitBreaker {
	if in == nil {
		return nil
	}
	out := new(EndpointCircuitBreaker)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HashPolicy) DeepCopyInto(out *HashPolicy) {
	*out = *in
	if in.Header != nil {
		in, out := &in.Header, &out.Header
		*out = new(HashPolicyHeader)
		**out = **in
	}
	if in.Cookie != nil {
		in, out := &in.Cookie, &out.Cookie
		*out = new(HashPolicyCookie)
		(*in).DeepCopyInto(*out)
	}
	if in.ConnectionProperties != nil {
		in, out := &in.ConnectionProperties, &out.ConnectionProperties
		*out = new(HashPolicyConnectionProperties)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HashPolicy.
func (in *HashPolicy) DeepCopy() *HashPolicy {
	if in == nil {
		return nil
	}
	out := new(HashPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HashPolicyConnectionProperties) DeepCopyInto(out *HashPolicyConnectionProperties) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HashPolicyConnectionProperties.
func (in *HashPolicyConnectionProperties) DeepCopy() *HashPolicyConnectionProperties {
	if in == nil {
		return nil
	}
	out := new(HashPolicyConnectionProperties)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HashPolicyCookie) DeepCopyInto(out *HashPolicyCookie) {
	*out = *in
	if in.Ttl != nil {
		in, out := &in.Ttl, &out.Ttl
		*out = new(time.Duration)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HashPolicyCookie.
func (in *HashPolicyCookie) DeepCopy() *HashPolicyCookie {
	if in == nil {
		return nil
	}
	out := new(HashPolicyCookie)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HashPolicyHeader) DeepCopyInto(out *HashPolicyHeader) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HashPolicyHeader.
func (in *HashPolicyHeader) DeepCopy() *HashPolicyHeader {
	if in == nil {
		return nil
	}
	out := new(HashPolicyHeader)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HeaderMatcher) DeepCopyInto(out *HeaderMatcher) {
	*out = *in
	if in.Present != nil {
		in, out := &in.Present, &out.Present
		*out = new(bool)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HeaderMatcher.
func (in *HeaderMatcher) DeepCopy() *HeaderMatcher {
	if in == nil {
		return nil
	}
	out := new(HeaderMatcher)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HeaderSize) DeepCopyInto(out *HeaderSize) {
	*out = *in
	in.HeaderSize.DeepCopyInto(&out.HeaderSize)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HeaderSize.
func (in *HeaderSize) DeepCopy() *HeaderSize {
	if in == nil {
		return nil
	}
	out := new(HeaderSize)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HeaderSizeSetting) DeepCopyInto(out *HeaderSizeSetting) {
	*out = *in
	if in.MaxBytes != nil {
		in, out := &in.MaxBytes, &out.MaxBytes
		*out = new(int)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HeaderSizeSetting.
func (in *HeaderSizeSetting) DeepCopy() *HeaderSizeSetting {
	if in == nil {
		return nil
	}
	out := new(HeaderSizeSetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HealthCheck) DeepCopyInto(out *HealthCheck) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HealthCheck.
func (in *HealthCheck) DeepCopy() *HealthCheck {
	if in == nil {
		return nil
	}
	out := new(HealthCheck)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Ingress) DeepCopyInto(out *Ingress) {
	*out = *in
	in.Listener.DeepCopyInto(&out.Listener)
	in.VirtualHost.DeepCopyInto(&out.VirtualHost)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Ingress.
func (in *Ingress) DeepCopy() *Ingress {
	if in == nil {
		return nil
	}
	out := new(Ingress)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IpAllowDeny) DeepCopyInto(out *IpAllowDeny) {
	*out = *in
	if in.AllowCidrs != nil {
		in, out := &in.AllowCidrs, &out.AllowCidrs
		*out = make([]Cidr, len(*in))
		copy(*out, *in)
	}
	if in.DenyCidrs != nil {
		in, out := &in.DenyCidrs, &out.DenyCidrs
		*out = make([]Cidr, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IpAllowDeny.
func (in *IpAllowDeny) DeepCopy() *IpAllowDeny {
	if in == nil {
		return nil
	}
	out := new(IpAllowDeny)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KVP) DeepCopyInto(out *KVP) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KVP.
func (in *KVP) DeepCopy() *KVP {
	if in == nil {
		return nil
	}
	out := new(KVP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LeastRequestLbConfig) DeepCopyInto(out *LeastRequestLbConfig) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LeastRequestLbConfig.
func (in *LeastRequestLbConfig) DeepCopy() *LeastRequestLbConfig {
	if in == nil {
		return nil
	}
	out := new(LeastRequestLbConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Listener) DeepCopyInto(out *Listener) {
	*out = *in
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLS)
		(*in).DeepCopyInto(*out)
	}
	if in.TCPProxy != nil {
		in, out := &in.TCPProxy, &out.TCPProxy
		*out = new(TCPProxy)
		(*in).DeepCopyInto(*out)
	}
	if in.delegateTCPProxy != nil {
		in, out := &in.delegateTCPProxy, &out.delegateTCPProxy
		*out = new(TCPProxy)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Listener.
func (in *Listener) DeepCopy() *Listener {
	if in == nil {
		return nil
	}
	out := new(Listener)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PerFilterConfig) DeepCopyInto(out *PerFilterConfig) {
	*out = *in
	if in.IpAllowDeny != nil {
		in, out := &in.IpAllowDeny, &out.IpAllowDeny
		*out = new(IpAllowDeny)
		(*in).DeepCopyInto(*out)
	}
	if in.HeaderSize != nil {
		in, out := &in.HeaderSize, &out.HeaderSize
		*out = new(HeaderSize)
		(*in).DeepCopyInto(*out)
	}
	if in.Authz != nil {
		in, out := &in.Authz, &out.Authz
		*out = (*in).DeepCopy()
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PerFilterConfig.
func (in *PerFilterConfig) DeepCopy() *PerFilterConfig {
	if in == nil {
		return nil
	}
	out := new(PerFilterConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Redirect) DeepCopyInto(out *Redirect) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Redirect.
func (in *Redirect) DeepCopy() *Redirect {
	if in == nil {
		return nil
	}
	out := new(Redirect)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RetryPolicy) DeepCopyInto(out *RetryPolicy) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RetryPolicy.
func (in *RetryPolicy) DeepCopy() *RetryPolicy {
	if in == nil {
		return nil
	}
	out := new(RetryPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Route) DeepCopyInto(out *Route) {
	*out = *in
	if in.Delegate != nil {
		in, out := &in.Delegate, &out.Delegate
		*out = new(Delegate)
		**out = **in
	}
	if in.CorsPolicy != nil {
		in, out := &in.CorsPolicy, &out.CorsPolicy
		*out = (*in).DeepCopy()
	}
	if in.HeaderMatchers != nil {
		in, out := &in.HeaderMatchers, &out.HeaderMatchers
		*out = make([]HeaderMatcher, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.RetryPolicy != nil {
		in, out := &in.RetryPolicy, &out.RetryPolicy
		*out = new(RetryPolicy)
		**out = **in
	}
	if in.HashPolicies != nil {
		in, out := &in.HashPolicies, &out.HashPolicies
		*out = make([]HashPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.PerFilterConfig != nil {
		in, out := &in.PerFilterConfig, &out.PerFilterConfig
		*out = new(PerFilterConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.RequestHeadersToAdd != nil {
		in, out := &in.RequestHeadersToAdd, &out.RequestHeadersToAdd
		*out = make([]KVP, len(*in))
		copy(*out, *in)
	}
	if in.RequestHeadersToRemove != nil {
		in, out := &in.RequestHeadersToRemove, &out.RequestHeadersToRemove
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ResponseHeadersToAdd != nil {
		in, out := &in.ResponseHeadersToAdd, &out.ResponseHeadersToAdd
		*out = make([]KVP, len(*in))
		copy(*out, *in)
	}
	if in.ResponseHeadersToRemove != nil {
		in, out := &in.ResponseHeadersToRemove, &out.ResponseHeadersToRemove
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.RateLimits != nil {
		in, out := &in.RateLimits, &out.RateLimits
		*out = make([]*envoyapi.RateLimit, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = (*in).DeepCopy()
			}
		}
	}
	if in.Clusters != nil {
		in, out := &in.Clusters, &out.Clusters
		*out = make([]Cluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Redirect != nil {
		in, out := &in.Redirect, &out.Redirect
		*out = new(Redirect)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Route.
func (in *Route) DeepCopy() *Route {
	if in == nil {
		return nil
	}
	out := new(Route)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPProxy) DeepCopyInto(out *TCPProxy) {
	*out = *in
	if in.Delegate != nil {
		in, out := &in.Delegate, &out.Delegate
		*out = new(Delegate)
		**out = **in
	}
	if in.Clusters != nil {
		in, out := &in.Clusters, &out.Clusters
		*out = make([]Cluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPProxy.
func (in *TCPProxy) DeepCopy() *TCPProxy {
	if in == nil {
		return nil
	}
	out := new(TCPProxy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLS) DeepCopyInto(out *TLS) {
	*out = *in
	if in.CipherSuites != nil {
		in, out := &in.CipherSuites, &out.CipherSuites
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLS.
func (in *TLS) DeepCopy() *TLS {
	if in == nil {
		return nil
	}
	out := new(TLS)
	in.DeepCopyInto(out)
	return out
}
