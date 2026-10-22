//go:build windows

package apple

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Reproduce the upstream two-requests-per-connection failure independently of
// Apple and credentials, then exercise the real production GSA transport.
func TestGSAThirdRequestUsesFreshTLSConnection(t *testing.T) {
	var connections atomic.Int32
	type countKey struct{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := r.Context().Value(countKey{}).(*atomic.Int32)
		if count.Add(1) > 2 {
			w.WriteHeader(503)
		}
		w.Write([]byte("synthetic response"))
	}))
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		connections.Add(1)
		return context.WithValue(ctx, countKey{}, new(atomic.Int32))
	}
	server.StartTLS()
	defer server.Close()
	requestThree := func(client *http.Client) []int {
		codes := []int{}
		for i := 0; i < 3; i++ {
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			codes = append(codes, response.StatusCode)
		}
		return codes
	}
	baseline := requestThree(server.Client())
	if baseline[0] != 200 || baseline[1] != 200 || baseline[2] != 503 || connections.Load() != 1 {
		t.Fatal("fixture did not reproduce pooled third-request failure")
	}
	transport := appleTransport().(*scopedAppleTransport)
	defer transport.CloseIdleConnections()
	if transport.ordinary.DisableKeepAlives {
		t.Fatal("developer-service transport was changed")
	}
	transport.gsa.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	before := connections.Load()
	actual := requestThree(&http.Client{Transport: transport.gsa})
	for _, code := range actual {
		if code != 200 {
			t.Fatal("GSA request reused a rejected connection")
		}
	}
	if connections.Load()-before != 3 {
		t.Fatal("GSA did not create one TLS connection per request")
	}
}
