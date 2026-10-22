package apple

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"howett.net/plist"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testHeaders(context.Context) (map[string]string, error) {
	h := map[string]string{}
	for _, k := range requiredHeaders {
		h[k] = "synthetic-" + k
	}
	h["X-Apple-I-MD-RINFO"] = "84215040"
	return h, nil
}
func reply(data []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}
}
func encoded(value any) []byte {
	b, e := plist.Marshal(value, plist.XMLFormat)
	if e != nil {
		panic(e)
	}
	return b
}
func testSession() *Session {
	h, _ := testHeaders(context.Background())
	return &Session{Username: "offline@example.invalid", DSID: "synthetic-dsid", Token: "private-token", IdentityFP: fingerprint(h)}
}
func TestDeveloperRequestAndGzip(t *testing.T) {
	c := New(testHeaders)
	calls := 0
	c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "developerservices2.apple.com" || !strings.Contains(r.URL.Path, "/ios/listAppIds.action") {
			t.Fatal("wrong destination")
		}
		if r.Header.Get("X-Apple-GS-Token") != "private-token" {
			t.Fatal("missing token")
		}
		raw, _ := io.ReadAll(r.Body)
		body, e := parsePlist(raw)
		if e != nil || body["teamId"] != "TEAM1" || body["DTDK_Platform"] != "ios" {
			t.Fatal("wrong developer body")
		}
		var compressed bytes.Buffer
		w := gzip.NewWriter(&compressed)
		w.Write(encoded(map[string]any{"resultCode": 0, "appIds": []any{}}))
		w.Close()
		return reply(compressed.Bytes()), nil
	})
	if _, e := c.Request(context.Background(), testSession(), "listAppIds", nil, "TEAM1"); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("wrong request count")
	}
}
func TestDeveloperInputAndIdentityGuards(t *testing.T) {
	c := New(testHeaders)
	c.HTTPClient.Transport = roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("network must not run"); return nil, nil })
	ctx := context.Background()
	for _, action := range []string{"revokeDevelopmentCert", "deleteAppId", "x/y"} {
		if _, e := c.Request(ctx, testSession(), action, nil, "TEAM1"); e == nil {
			t.Fatal("unsupported action accepted")
		}
	}
	if _, e := c.Request(ctx, testSession(), "listTeams", map[string]any{"teamId": "override"}, ""); e == nil {
		t.Fatal("reserved field accepted")
	}
	session := testSession()
	session.IdentityFP = "changed"
	if _, e := c.Request(ctx, session, "listTeams", nil, ""); e == nil {
		t.Fatal("identity drift accepted")
	}
}

func TestTransportBoundsAllowlistAndRedaction(t *testing.T) {
	c := New(testHeaders)
	c.HTTPClient.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid destination reached transport")
		return nil, nil
	})
	for _, url := range []string{"http://gsa.apple.com/x", "https://evil.invalid/x", "https://u:p@gsa.apple.com/x", "https://gsa.apple.com:444/x", "https://gsa.apple.com/x#fragment"} {
		if _, _, e := c.request(context.Background(), "GET", url, nil, nil); e == nil {
			t.Fatal("invalid URL accepted")
		}
	}
	for _, kind := range []string{"oversize", "gzip", "privateError", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			c.HTTPClient.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
				switch kind {
				case "oversize":
					return reply(bytes.Repeat([]byte{1}, maxResponse+1)), nil
				case "gzip":
					var b bytes.Buffer
					w := gzip.NewWriter(&b)
					w.Write(bytes.Repeat([]byte{1}, maxResponse+1))
					w.Close()
					return reply(b.Bytes()), nil
				case "redirect":
					r := reply(nil)
					r.StatusCode = 302
					r.Header.Set("Location", "https://evil.invalid/private-token")
					return r, nil
				default:
					return reply(encoded(map[string]any{"resultCode": 1100, "resultString": "private-token user@example.invalid"})), nil
				}
			})
			_, e := c.Request(context.Background(), testSession(), "listTeams", nil, "")
			if e == nil || strings.Contains(e.Error(), "private-token") || strings.Contains(e.Error(), "user@example.invalid") {
				t.Fatal("failed bound/redaction")
			}
		})
	}
}
func encryptSPD(key []byte, value any) []byte {
	plain := encoded(value)
	n := 16 - len(plain)%16
	plain = append(plain, bytes.Repeat([]byte{byte(n)}, n)...)
	block, _ := aes.NewCipher(mac(key, []byte("extra data key:")))
	cipher.NewCBCEncrypter(block, mac(key, []byte("extra data iv:"))[:16]).CryptBlocks(plain, plain)
	return plain
}
func encryptToken(key []byte, value any) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	nonce := bytes.Repeat([]byte{3}, 16)
	out := append([]byte("XYZ"), nonce...)
	return append(out, gcm.Seal(nil, nonce, encoded(value), []byte("XYZ"))...)
}
func TestAuthenticatedDecryptionAndTampering(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	blob := encryptSPD(key, map[string]any{"adsid": "synthetic"})
	if _, e := decryptSPD(key, blob); e != nil {
		t.Fatal(e)
	}
	blob[len(blob)-1] ^= 1
	if _, e := decryptSPD(key, blob); e == nil {
		t.Fatal("CBC padding corruption accepted")
	}
	token := encryptToken(key, map[string]any{"test": "value"})
	if _, e := decryptToken(key, token); e != nil {
		t.Fatal(e)
	}
	token[len(token)-1] ^= 1
	if _, e := decryptToken(key, token); e == nil {
		t.Fatal("GCM tampering accepted")
	}
}

// Independent server exponentiation uses (A * v^u)^b rather than the client's
// subtraction/exponent formula; fixed oracle vectors additionally pin all bytes.
func TestLoginWithIndependentServer(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "MFA-and-application-token"}[mfa], func(t *testing.T) { testLoginWithIndependentServer(t, mfa) })
	}
}
func testLoginWithIndependentServer(t *testing.T, requireMFA bool) {
	testLoginWithIndependentServerPolicy(t, requireMFA, windowsAuthentication())
}
func TestExplicitWindowsAuthKitWithIndependentServer(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "MFA"}[mfa], func(t *testing.T) { testLoginWithIndependentServerPolicy(t, mfa, true) })
	}
}
func TestPortableAuthKitWithIndependentServer(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "MFA"}[mfa], func(t *testing.T) { testLoginWithIndependentServerPolicy(t, mfa, false, true) })
	}
}

func testLoginWithIndependentServerPolicy(t *testing.T, requireMFA, windowsAuthKit bool, portable ...bool) {
	providerCalls := 0
	c := newClient(func(ctx context.Context) (map[string]string, error) {
		providerCalls++
		h, err := testHeaders(ctx)
		h["X-Apple-I-MD"] = strings.Repeat("synthetic-OTP", providerCalls)
		return h, err
	}, windowsAuthKit)
	portablePolicy := len(portable) != 0 && portable[0]
	const macDescription = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	if portablePolicy {
		var err error
		c, err = NewPortableAuthKit(c.provider, macDescription)
		if err != nil {
			t.Fatal(err)
		}
	}
	username, password := "offline@example.invalid", "synthetic password only!"
	var shared, m1, m2 []byte
	calls := 0
	completions := 0
	var firstCPD map[string]any
	sk := bytes.Repeat([]byte{8}, 32)
	server := roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/auth/verify/trusteddevice" || r.URL.Path == "/grandslam/GsService2/validate" {
			if !requireMFA {
				t.Fatal("unexpected verification request")
			}
			if portablePolicy && (r.Header.Get("X-MMe-Client-Info") != macDescription || r.Header.Get("User-Agent") != windowsAuthenticationUserAgent) {
				t.Fatal("portable verification metadata mismatch")
			}
			return reply(encoded(map[string]any{"ec": 0})), nil
		}
		raw, _ := io.ReadAll(r.Body)
		packet, e := parsePlist(raw)
		if e != nil {
			t.Fatal(e)
		}
		body := packet["Request"].(map[string]any)
		if portablePolicy {
			wantDescription, wantAgent := macDescription, "Xcode"
			passwordRequest := body["o"] == "init" || body["o"] == "complete"
			if marked, _ := r.Context().Value(portableSRPContextKey{}).(bool); marked != passwordRequest {
				t.Fatal("password transport marker differs from operation")
			}
			if body["o"] == "init" || body["o"] == "complete" {
				wantDescription = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
				wantAgent = windowsAuthenticationUserAgent
			}
			if r.Header.Get("X-MMe-Client-Info") != wantDescription || r.Header.Get("User-Agent") != wantAgent || r.Header.Get("Accept") != "*/*" || r.Header.Get("X-Apple-I-MD-M") == "" || r.Header.Get("X-Mme-Device-Id") == "" || r.Header.Get("X-Xcode-Version") != "" || r.Header.Get("X-Apple-App-Info") != "" || r.Header.Get("Connection") != "" {
				t.Fatal("portable GSA metadata mismatch")
			}
			clientData := body["cpd"].(map[string]any)
			if clientData["pbe"] != true || clientData["bootstrap"] != true || clientData["AppleIDClientIdentifier"] == nil {
				t.Fatal("portable CPD must use full native policy")
			}
		}
		if windowsAuthKit {
			if r.Header.Get("User-Agent") != "akd/1.0 CFNetwork/808.1.4" || r.Header.Get("X-Apple-I-MD-M") != "" || r.Header.Get("X-Mme-Device-Id") != "" || r.Header.Get("Accept") != "text/x-xml-plist" || r.Header.Get("X-Apple-App-Info") != appID || r.Header.Get("X-Xcode-Version") != "27.0 (27A5218g)" || r.Header.Get("Connection") != "close" {
				t.Fatal("GSA HTTP headers differ from AltServer")
			}
			clientData := body["cpd"].(map[string]any)
			stableCPD := map[string]any{}
			for name, value := range clientData {
				if name != "X-Apple-I-MD" {
					stableCPD[name] = value
				}
			}
			if firstCPD == nil {
				firstCPD = stableCPD
			}
			if !reflect.DeepEqual(firstCPD, stableCPD) || len(clientData) != 9 || clientData["pbe"] != "false" || clientData["bootstrap"] != "true" || clientData["icscrec"] != "true" || clientData["prkgen"] != "true" || clientData["svct"] != "iCloud" {
				t.Fatal("GSA CPD changed across MFA/application-token operations or differs from AltServer")
			}
			for _, name := range []string{"wpbe", "ckgen", "AppleIDClientIdentifier", "X-Apple-I-Device-Configuration-Mode"} {
				if _, ok := clientData[name]; ok {
					t.Fatal("unexpected CPD field")
				}
			}
		}
		result := map[string]any{"Status": map[string]any{"ec": 0}}
		switch body["o"] {
		case "init":
			if windowsAuthKit && len(body["A2k"].([]byte)) != 256 {
				t.Fatal("SRP public key is not fixed-width")
			}
			A := integer(body["A2k"].([]byte))
			n, _ := new(big.Int).SetString(primeHex, 16)
			g := big.NewInt(2)
			b := integer(digest([]byte("server ephemeral")))
			salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
			p, _ := passwordKey(password, salt, 1000, "s2k")
			x := integer(digest(salt, digest([]byte(":"), p)))
			v := new(big.Int).Exp(g, x, n)
			k := integer(digest(pad(n), pad(g)))
			B := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, b, n))
			B.Mod(B, n)
			u := integer(digest(pad(A), pad(B)))
			S := new(big.Int).Exp(new(big.Int).Mod(new(big.Int).Mul(A, new(big.Int).Exp(v, u, n)), n), b, n)
			shared = digest(minimum(S))
			hn, hg := digest(minimum(n)), digest(pad(g))
			for i := range hn {
				hn[i] ^= hg[i]
			}
			m1 = digest(hn, digest([]byte(username)), salt, minimum(A), minimum(B), shared)
			m2 = digest(minimum(A), m1, shared)
			result["s"] = salt
			result["B"] = minimum(B)
			result["i"] = 1000
			result["sp"] = "s2k"
			result["c"] = "continuation"
		case "complete":
			completions++
			if requireMFA && completions == 1 {
				result["Status"] = map[string]any{"ec": 0, "au": "trustedDeviceSecondaryAuth"}
			}
			if !bytes.Equal(body["M1"].([]byte), m1) {
				t.Fatal("independent server rejected client proof")
			}
			result["M2"] = m2
			result["spd"] = encryptSPD(shared, map[string]any{"adsid": "synthetic-dsid", "GsIdmsToken": "private-idms", "sk": sk, "c": []byte("token-challenge")})
		case "apptokens":
			if !bytes.Equal(body["checksum"].([]byte), mac(sk, []byte("apptokenssynthetic-dsid"+appID))) {
				t.Fatal("wrong checksum")
			}
			result["et"] = encryptToken(sk, map[string]any{"t": map[string]any{appID: map[string]any{"token": "private-token"}}})
		default:
			t.Fatal("unexpected auth operation")
		}
		return reply(encoded(map[string]any{"Response": result})), nil
	})
	c.HTTPClient.Transport = server
	if portablePolicy {
		routed := &portableAuthTransport{
			srp: roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/grandslam/GsService2" {
					t.Fatal("wrong password route")
				}
				return server.RoundTrip(r)
			}),
			ordinary: roundTrip(func(r *http.Request) (*http.Response, error) {
				if password, _ := r.Context().Value(portableSRPContextKey{}).(bool); password {
					t.Fatal("password request reached normal transport")
				}
				return server.RoundTrip(r)
			}),
		}
		observed := 0
		c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { observed++; return routed.RoundTrip(r) })
		defer func() {
			if observed != calls {
				t.Error("outer transport observer missed requests")
			}
		}()
	}
	var challenge func(Challenge) (string, error)
	if requireMFA {
		challenge = func(value Challenge) (string, error) {
			if value.Kind != "trusted" {
				t.Fatal("unexpected challenge")
			}
			return "123456", nil
		}
	}
	session, e := c.Login(context.Background(), username, password, challenge)
	if e != nil {
		t.Fatal(e)
	}
	expectedCalls := 3
	if requireMFA {
		expectedCalls = 7
	}
	if session.Token != "private-token" || calls != expectedCalls {
		t.Fatal("login did not complete")
	}
	expectedProviderCalls := 2
	if requireMFA {
		expectedProviderCalls = 4
	}
	if windowsAuthKit && providerCalls != expectedProviderCalls {
		t.Fatal("fresh OTPs were not generated at MFA and token boundaries")
	}
}
func TestTrustedAndSMSChallengeCallbacks(t *testing.T) {
	for _, method := range []string{"trusted", "sms"} {
		t.Run(method, func(t *testing.T) {
			c := New(testHeaders)
			puts, posts := 0, 0
			c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if method == "trusted" {
					return reply(encoded(map[string]any{"ec": 0})), nil
				}
				if r.Method == "GET" {
					return reply([]byte(`{"trustedPhoneNumbers":[{"id":1,"number":"***1"},{"id":2,"number":"***2"}]}`)), nil
				}
				if r.Method == "PUT" {
					puts++
				}
				if r.Method == "POST" {
					posts++
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if body["phoneNumber"].(map[string]any)["id"] != float64(2) {
						t.Fatal("wrong phone")
					}
				}
				return reply([]byte(`{}`)), nil
			})
			h, _ := testHeaders(context.Background())
			e := c.twoFactor(context.Background(), map[string]any{"adsid": "d", "GsIdmsToken": "t"}, h, method, func(ch Challenge) (string, error) {
				if ch.Kind == "phone" {
					if len(ch.Phones) != 2 {
						t.Fatal("missing choices")
					}
					return "2", nil
				}
				return "123456", nil
			}, false)
			if e != nil {
				t.Fatal(e)
			}
			if method == "sms" && (puts != 1 || posts != 1) {
				t.Fatal("missing SMS operations")
			}
		})
	}
}
