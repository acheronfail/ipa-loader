package apple

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net/http"
)

// Apple publishes this public root at
// https://www.apple.com/appleca/AppleIncRootCertificate.cer .
// SHA256 b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024.
// GSA uses this Apple PKI chain, which is absent from some Windows root stores.
//
//go:embed certificates/AppleIncRootCertificate.cer
var appleRootDER []byte

type scopedAppleTransport struct{ ordinary, gsa *http.Transport }

type portableSRPContextKey struct{}

// Keep routing below HTTPClient.Transport so caller-provided observers can wrap
// the entire exchange without bypassing the password transport policy.
type portableAuthTransport struct{ ordinary, srp http.RoundTripper }

func (t *portableAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if password, _ := req.Context().Value(portableSRPContextKey{}).(bool); password && req.URL.Hostname() == "gsa.apple.com" {
		return t.srp.RoundTrip(req)
	}
	return t.ordinary.RoundTrip(req)
}

func (t *portableAuthTransport) CloseIdleConnections() {
	for _, transport := range []http.RoundTripper{t.ordinary, t.srp} {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func appleTransport() http.RoundTripper { return appleTransportWithPolicy(windowsAuthentication()) }

func appleTransportWithPolicy(windowsAuthKit bool) http.RoundTripper {
	ordinary := http.DefaultTransport.(*http.Transport).Clone()
	gsa := ordinary.Clone()
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	root, err := x509.ParseCertificate(appleRootDER)
	if err != nil {
		panic("invalid embedded Apple public root certificate")
	}
	roots.AddCert(root)
	gsa.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if windowsAuthKit {
		// AltSign #52: Apple's GSA edge can reject the third request on one
		// connection. Disable both HTTP/1 keep-alive and HTTP/2 multiplexing.
		gsa.DisableKeepAlives = true
		gsa.MaxConnsPerHost = 1
		gsa.ForceAttemptHTTP2 = false
		gsa.Protocols = new(http.Protocols)
		gsa.Protocols.SetHTTP1(true)
	}
	return &scopedAppleTransport{ordinary: ordinary, gsa: gsa}
}

func (t *scopedAppleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && req.URL.Hostname() == "gsa.apple.com" && (req.URL.Port() == "" || req.URL.Port() == "443") {
		return t.gsa.RoundTrip(req)
	}
	return t.ordinary.RoundTrip(req)
}

func (t *scopedAppleTransport) CloseIdleConnections() {
	t.ordinary.CloseIdleConnections()
	t.gsa.CloseIdleConnections()
}
