package annotations

const (
	// K8s Ingress annotations
	IC        = "kubernetes.io/ingress.class"
	AllowHTTP = "kubernetes.io/ingress.allow-http"

	// Ingress annotations (TODO: support "projectcontour.io" equivalent)
	ForceSSL = "ingress.kubernetes.io/force-ssl-redirect"

	// Service annotations
	H2  = "contour.heptio.com/upstream-protocol.h2"
	H2C = "contour.heptio.com/upstream-protocol.h2c"
	TLS = "contour.heptio.com/upstream-protocol.tls"

	// Ingress annotations (TODO: support "projectcontour.io" equivalent)
	MinTLSVersion   = "contour.heptio.com/tls-minimum-protocol-version"
	ResponseTimeout = "contour.heptio.com/response-timeout" // TODO(lrouquet) - unused
	RequestTimeout  = "contour.heptio.com/request-timeout"  // legacy
	RetryOn         = "contour.heptio.com/retry-on"         // TODO(lrouquet) - unused
	NumRetry        = "contour.heptio.com/num-retries"      // TODO(lrouquet) - unused
	PerTryTimeout   = "contour.heptio.com/per-try-timeout"  // TODO(lrouquet) - unused
	WebsocketRoutes = "contour.heptio.com/websocket-routes" // TODO(lrouquet) - unused

	// IngressRoute annotation (legacy service support)
	Hosts        = "adobeplatform.adobe.io/hosts"
	CreatedEpoch = "kapcom.adobe.io/created-epoch"
	ServiceId    = "adobe.serviceid"

	// for migration between CRDs
	Priority = "kapcom.adobe.io/priority"
)
