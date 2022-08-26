# ir2proxy [![Build Status](https://travis-ci.com/projectcontour/ir2proxy.svg?branch=main)](https://travis-ci.com/projectcontour/ir2proxy) [![Go Report Card](https://goreportcard.com/badge/github.com/projectcontour/ir2proxy)](https://goreportcard.com/report/github.com/projectcontour/ir2proxy) ![GitHub release](https://img.shields.io/github/release/projectcontour/ir2proxy.svg) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

ir2proxy is a set of tool to convert Contour's IngressRoute resources to HTTPProxy resources.

It was forked from upstream contour to add Adobe's changes made to both ingressroute and httpproxy 


## Features

ir2proxy can translate an IngressRoute object to an HTTPProxy object.
The full featureset of IngressRoute should be translated correctly.
If not, please [log an issue](https://git.corp.adobe.com/adobe-platform/ir2proxy/issues), specifying what didn't work and supplying the sanitized IngressRoute YAML.

This fork adds `kubectl-kapcom` which plugs in to kubectl as a means to help convert existing ingressroute manifests already present in kubernetes cluster 


## Migration
Prep audit comparing Adobe additions to both ingressroutes and httpproxy.

[Here](https://git.corp.adobe.com/gist/fortescu/1aed3013677099a0b657a2dd673d8c5d)

## Usage


### kubectl-kapcom
The kubectl plugin `ir2proxy` performs the same transformation as the original tool except it uses kubernetes as ingressroute source.

```
go build -o kubectl-kapcom ./cmd/kubectl-kapcom
ln -s `pwd`/kubectl-kapcom /usr/local/bin/kubectl-kapcom
kubectl kapcom ir2proxy -A
```

#### examples
> Switch to a dev cluster

```
k ctx ethos01-dev-va6
```
- Target a single ingressroute
```
kubectl kapcom  ir2proxy -n laurent   hello 
```

- Target a namespace

```
kubectl kapcom  ir2proxy -n ns-team-cgw-e2e-testing 
```

- Target all namespaces

```
kubectl kapcom  ir2proxy -A
```

### ir2proxy 
`ir2proxy` is intended for taking a yaml file containing one or more valid IngressRoute objects, and then outputting translated HTTPProxy objects to stdout.

Logging is done to stderr.

To use the tool, just run it with a filename as input.

```sh
$ ir2proxy basic.ingressroute.yaml
---
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: basic
  namespace: default
spec:
  routes:
  - conditions:
    - prefix: /
    services:
    - name: s1
      port: 80
  virtualhost:
    fqdn: foo-basic.bar.com
status: {}
```

Standalone `ir2proxy`'s intended mode of operation is in a one-file-at-a-time manner, so it's easier to use it in a Unix pipe.


## Installation

### Homebrew
>  The homebrew version does not account for kapcom ingressroute and httpproxies schema changes

### Requirements
- Go version 1.19
- kubectl

> MacOS
```
  brew update
  HOMEBREW_NO_AUTO_UPDATE=1 brew install go@1.19
  HOMEBREW_NO_AUTO_UPDATE=1 brew install kubectl
```

### kubectl-kapcom

```
go build -o kubectl-kapcom ./cmd/kubectl-kapcom
sudo ln -s `pwd`/kubectl-kapcom /usr/local/bin/kubectl 
```

### ir2proxy
```
go build -o kubectl-kapcom ./cmd/kubectl-kapcom
```
## Gap Analysis
The following table depicts the *Adobe* specific gaps for changes between ingressroute and httpproxy


| ingressroute CRD reference | httpproxy supported? | Notes|
--- |  --- | ---|
|route.RequestHeadersPolicy| Yes||
|route.ResponseHeadersPolicy| Yes||
|route.perFilterConfig| Yes||
|route.enableSPDY|No||
|route.headerMatch|Yes|Moved to route.conditions|
|route.services.service.idleTimeout|Yes| Moved to route.timeoutPolicy|
|route.services.service.perPodMaxConnections| No||
|route.services.service.perPodMaxPendingRequests|No||
|route.services.service.perPodMaxRequests|No||
|route.services.service.connectTimeout|No||
|route.HashPolicies|No|Strategy='RequestHash' should be supported per [For more](https://projectcontour.io/docs/v1.19.0/config/request-routing/#load-balancing-strategy).  However, [kapcom ignores RequestHash](https://git.corp.adobe.com/adobe-platform/kapcom/blob/main/contour/v1/httpproxy_xlate.go#L126)

### Non-homebrew

```
docker run -it -v `pwd`:/go/src/ir2hp.adobe.com -w /go/src/ir2hp.adobe.com -e CGO_ENABLED=0 golang:1.18.5 go build -o kubectl-kapcom ./cmd/kubectl-kapcom
```
> Generates a statically linked linux binary that can be run from any linux container/host
 
Go to the [releases](https://git.corp.adobe.com/adobe-platform/ir2proxy/releases) page and download the latest version.

## Possible issues with conversion and what to do about them

### Missing Adobe HTTProxy fields present in ingressroute
> For a deep dive into Adobe ingressroute and httpproxy changes [see](https://git.corp.adobe.com/gist/fortescu/1aed3013677099a0b657a2dd673d8c5d)

### Prefix behavior in IngressRoute vs HTTPProxy

In IngressRoute, delegation was a route-level construct, that required that the delegated IngressRoutes have the full prefix, including the delegation prefix.
So a nonroot Ingressroute that wanted to accept traffic for `/foo/bar` would have a `match` entry of `/foo/bar`.

For HTTPProxy, inclusion is a top-level construct, and the included HTTPProxy does *not* need to have the full prefix, and can be included at multiple paths if required.
So a nonroot HTTPProxy that wanted to accept traffic for `/foo/bar` would have a `prefix` `condition` of `/bar`, and be included using a `prefix` `condition` of `/foo`.

`ir2proxy` tries to guess what the prefix should be, and puts its guess into generated nonroot HTTPProxy objects.
It will warn you on stderr and in the generated file what its guess means if it's not sure.
(For some specific cases, the tool can be sure what you mean.)


### Load Balancing Strategy

In IngressRoute, setting the load balancing strategy was originally designed as a route-level default that could be overwritten by a service-level setting.
However, only the service-level setting was implemented.

HTTPProxy currently only has the route-level setting implemented, so `ir2proxy` will take the first setting of `strategy` in IngressRoute to be the correct setting for HTTPProxy.

#### Kapcom sticky session
Kapcom ingressroute introduced `HashPolicy` at the route level to support sticky sessions.  
Projectcontour's httpproxy supports sticky sessions through Strategy=Cookie and Strategy=RequestHeader set at the service level.  Kapcom's httpproxy implementation does not support either yet.

ir2proxy and kubectl-kapcom plugin both set the lbpolicy=RequestHash as it is a no-op in kapcom but will future proof the conversion (i.e. nothing will need to be done to this tool when kapcom implements it).

A warning will be output to stderr and as a comment in the file.

### Healthchecks

In IngressRoute, healthchecks were only configurable at a service level, not defaulted at a route level.

In HTTPProxy, healthchecks are only configurable at a route level.
Accordingly, `ir2proxy` will take the healthcheck found and record it at the HTTPProxy Route level.
This means that for multiple healthchecks, the last will take precedence.

A warning will be output to stderr and as a comment in the file.



## Other notes

Kapcom's contour apis use some structures from kapcom/xlate which has the effect - through xlate dependencies - of invoking kapcom/config.go->init() even though on the ClientSets are needed.

Calling config.go:init() parses kapcom's options and outputs settings to `stdout` which directly interferes with the ability of these tools to be used in a unix exec chain.  

As a remeditaion, kapcom was forked and the problem fixed on v1.18.2 which is reflected in go.mod.