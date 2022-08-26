// +build !ignore_autogenerated

// Copyright 2021 Adobe. All Rights Reserved.

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CheckSettings) DeepCopyInto(out *CheckSettings) {
	*out = *in
	if in.ContextExtensions != nil {
		in, out := &in.ContextExtensions, &out.ContextExtensions
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CheckSettings.
func (in *CheckSettings) DeepCopy() *CheckSettings {
	if in == nil {
		return nil
	}
	out := new(CheckSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExtAuthz) DeepCopyInto(out *ExtAuthz) {
	*out = *in
	out.GrpcService = in.GrpcService
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExtAuthz.
func (in *ExtAuthz) DeepCopy() *ExtAuthz {
	if in == nil {
		return nil
	}
	out := new(ExtAuthz)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExtAuthzPerRoute) DeepCopyInto(out *ExtAuthzPerRoute) {
	*out = *in
	if in.CheckSettings != nil {
		in, out := &in.CheckSettings, &out.CheckSettings
		*out = new(CheckSettings)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExtAuthzPerRoute.
func (in *ExtAuthzPerRoute) DeepCopy() *ExtAuthzPerRoute {
	if in == nil {
		return nil
	}
	out := new(ExtAuthzPerRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrpcService) DeepCopyInto(out *GrpcService) {
	*out = *in
	out.SocketAddress = in.SocketAddress
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrpcService.
func (in *GrpcService) DeepCopy() *GrpcService {
	if in == nil {
		return nil
	}
	out := new(GrpcService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Sidecar) DeepCopyInto(out *Sidecar) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Sidecar.
func (in *Sidecar) DeepCopy() *Sidecar {
	if in == nil {
		return nil
	}
	out := new(Sidecar)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Sidecar) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarFilters) DeepCopyInto(out *SidecarFilters) {
	*out = *in
	if in.ExtAuthz != nil {
		in, out := &in.ExtAuthz, &out.ExtAuthz
		*out = new(ExtAuthz)
		**out = **in
	}
	if in.ExtAuthzPerRoute != nil {
		in, out := &in.ExtAuthzPerRoute, &out.ExtAuthzPerRoute
		*out = new(ExtAuthzPerRoute)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarFilters.
func (in *SidecarFilters) DeepCopy() *SidecarFilters {
	if in == nil {
		return nil
	}
	out := new(SidecarFilters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarIngress) DeepCopyInto(out *SidecarIngress) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarIngress.
func (in *SidecarIngress) DeepCopy() *SidecarIngress {
	if in == nil {
		return nil
	}
	out := new(SidecarIngress)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarList) DeepCopyInto(out *SidecarList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Sidecar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarList.
func (in *SidecarList) DeepCopy() *SidecarList {
	if in == nil {
		return nil
	}
	out := new(SidecarList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SidecarList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarSpec) DeepCopyInto(out *SidecarSpec) {
	*out = *in
	out.Ingress = in.Ingress
	in.Filters.DeepCopyInto(&out.Filters)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarSpec.
func (in *SidecarSpec) DeepCopy() *SidecarSpec {
	if in == nil {
		return nil
	}
	out := new(SidecarSpec)
	in.DeepCopyInto(out)
	return out
}
