# A note on CDS warming

CDS must be warmed with EDS. At one point we had a `warmEDS` function that was
at the bottom of `handleDDR` but this doesn't work because Envoy rejects it
(at least on startup) with:

```
[warning][config] [source/common/config/new_grpc_mux_impl.cc:83]
Dropping received DeltaDiscoveryResponse (with version ) for non-existent
subscription type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment.
```

In a steady state there appears to be a race condition with CDS subscribing to
the corresponding EDS "instance" which causes intermittent `503 UH`

See https://git.corp.adobe.com/adobe-platform/kapcom/issues/287 for more
