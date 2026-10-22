// Package apple implements the independently reconstructed Apple developer login
// path. Callers may persist sessions in an OS credential vault; passwords,
// responses and tokens are never logged.
package apple

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type HeaderProvider func(context.Context) (map[string]string, error)
type Session struct{ Username, DSID, Token, IdentityFP string }

func (*Session) String() string   { return "Apple session (private)" }
func (*Session) GoString() string { return "Apple session (private)" }

type Team struct {
	ID, Name                    string
	AppIDsUnlimited, LimitKnown bool
	AppIDLimit                  int
	AppIDsAvailable             int
	AvailabilityKnown           bool
}
type Phone struct {
	ID    int
	Label string
}
type Challenge struct {
	Kind, Message string
	Phones        []Phone
}
type Client struct {
	windowsAuthKit  bool
	portableAuthKit bool
	provider        HeaderProvider
	HTTPClient      *http.Client
}

type Error struct {
	Message string
	Code    int
}

func (e *Error) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("%s (code %d)", e.Message, e.Code)
	}
	return e.Message
}
func failure(message string) error { return &Error{Message: message} }
func appleError(code int) error {
	message := "Apple request failed"
	switch code {
	case -20101, -22406:
		message = "Apple rejected the credentials"
	case -22421:
		message = "Apple rejected the local authentication headers"
	case -21669:
		message = "Apple rejected the verification code"
	case 1100:
		message = "The Apple session expired; sign in again"
	case 4550:
		message = "Review the developer agreement in Apple’s account interface"
	case 9401:
		message = "This app’s identifier is unavailable for this account"
	case 9120:
		message = "This account has reached its App ID limit; try again after an existing App ID expires"
	case 9412:
		message = "Apple rejected this app’s bundle identifier as invalid"
	case 7460:
		message = "Apple rejected the signing request because the account has reached its development certificate limit"
	}
	return &Error{Message: message, Code: code}
}
func New(provider HeaderProvider) *Client {
	return newClient(provider, windowsAuthentication())
}

// NewWindowsAuthKit selects the recovered Windows AuthKit request policy on any
// host: padded SRP public key, string CPD, fresh GSA connections and OTP refresh.
// The caller still supplies its own anisette provider.
func NewWindowsAuthKit(provider HeaderProvider) *Client {
	return newClient(provider, true)
}

// NewPortableAuthKit selects the independently validated request policy for
// portable ADI providers. Password exchanges use fresh connections and Windows
// AuthKit metadata; application tokens and developer services use the supplied
// Mac description consistently. The provider's maps are never mutated.
func NewPortableAuthKit(provider HeaderProvider, macClientDescription string) (*Client, error) {
	if provider == nil || len(macClientDescription) == 0 || len(macClientDescription) > 4096 || strings.IndexFunc(macClientDescription, func(r rune) bool { return r < 32 || r > 126 }) >= 0 || (!strings.Contains(macClientDescription, "<macOS;") && !strings.Contains(macClientDescription, "<Mac OS X;")) {
		return nil, failure("A valid Mac client description and header provider are required")
	}
	c := newClient(func(ctx context.Context) (map[string]string, error) {
		headers, err := provider(ctx)
		if err != nil {
			return nil, err
		}
		headers = cloneHeaders(headers)
		headers["X-MMe-Client-Info"] = macClientDescription
		return headers, nil
	}, false)
	c.portableAuthKit = true
	c.HTTPClient.Transport = &portableAuthTransport{ordinary: c.HTTPClient.Transport, srp: appleTransportWithPolicy(true)}
	return c, nil
}

func newClient(provider HeaderProvider, windowsAuthKit bool) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{windowsAuthKit: windowsAuthKit, provider: provider, HTTPClient: &http.Client{Transport: appleTransportWithPolicy(windowsAuthKit), Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
