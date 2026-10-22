// Package purego provisions independent ADI state and produces authentication
// headers without loading an Apple ADI implementation.
package purego

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
	"ipa-loader/app/internal/anisette/adimath"
)

// Match the Android ADI format instead of declaring a macOS implementation.
// Reference: xtool-org/xtool commit146f603, DeviceInfo.swift (2026-10-13).
const clientInfo = "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

// URL-bag identity for machine provisioning. Login metadata is separate.
const provisioningClientInfo = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
const lookupURL = "https://gsa.apple.com/grandslam/GsService2/lookup"
const bodyLimit = 4 << 20

// State contains reusable machine secrets; serialize only to private storage.
// Version identifies our owned format, not Apple's adi.pb.
type State struct {
	Version   int                         `json:"version"`
	DeviceID  string                      `json:"device_id"`
	LocalUser string                      `json:"local_user"`
	Routing   string                      `json:"routing"`
	Machine   adimath.AndroidMachineState `json:"machine"`
}

func (*State) String() string   { return "Pure-Go anisette state (private)" }
func (*State) GoString() string { return "Pure-Go anisette state (private)" }

func approvedURL(address string) bool {
	u, e := url.Parse(address)
	return e == nil && u.Scheme == "https" && u.User == nil && u.Fragment == "" && (u.Port() == "" || u.Port() == "443") && (u.Hostname() == "apple.com" || strings.HasSuffix(u.Hostname(), ".apple.com"))
}

func (s *State) metadata(now time.Time) map[string]string {
	return map[string]string{
		"X-Mme-Device-Id":       s.DeviceID,
		"X-Apple-I-MD-LU":       s.LocalUser,
		"X-MMe-Client-Info":     clientInfo,
		"X-Apple-I-SRL-NO":      "0",
		"X-Apple-I-MD-RINFO":    s.Routing,
		"X-Apple-I-Client-Time": now.UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-Locale":        "en_US",
		"X-Apple-I-TimeZone":    "UTC",
	}
}

// Headers computes fresh MID/OTP locally. It makes no network request.
func (s *State) Headers(ctx context.Context) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.Version != 1 || s.Machine.Environment != -2 || s.DeviceID == "" || len(s.LocalUser) != 64 {
		return nil, errors.New("invalid pure-Go anisette state")
	}
	if _, err := strconv.ParseInt(s.Routing, 10, 64); err != nil {
		return nil, errors.New("invalid pure-Go routing information")
	}
	now := time.Now()
	mid, otp := s.Machine.OTP(now.Unix())
	h := s.metadata(now)
	h["X-Apple-I-MD-M"] = base64.StdEncoding.EncodeToString(mid[:])
	h["X-Apple-I-MD"] = base64.StdEncoding.EncodeToString(otp[:])
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

func request(ctx context.Context, client *http.Client, state *State, method, address string, body []byte, stage string) (map[string]any, error) {
	if !approvedURL(address) {
		return nil, errors.New("provisioning endpoint must be Apple HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("could not create %s request", stage)
	}
	for k, v := range state.metadata(time.Now()) {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-MMe-Client-Info", provisioningClientInfo)
	req.Header.Set("User-Agent", "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Apple-Client-App-Name", "Setup")
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !approvedURL(req.URL.String()) {
			return errors.New("invalid provisioning redirect")
		}
		return nil
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	response, err := c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s HTTPS failed", stage)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%s HTTP %d", stage, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, bodyLimit+1))
	if err != nil || len(data) > bodyLimit {
		return nil, fmt.Errorf("invalid %s response size", stage)
	}
	var result map[string]any
	if _, err = plist.Unmarshal(data, &result); err != nil || result == nil {
		return nil, fmt.Errorf("invalid %s property list", stage)
	}
	return result, nil
}
func packetField(m map[string]any, key string) ([]byte, error) {
	switch v := m[key].(type) {
	case string:
		raw, e := base64.StdEncoding.DecodeString(v)
		if e == nil && len(raw) > 0 && len(raw) <= bodyLimit {
			return raw, nil
		}
	case []byte:
		if len(v) > 0 && len(v) <= bodyLimit {
			return v, nil
		}
	}
	return nil, fmt.Errorf("invalid provisioning %s field", key)
}
func payload(request map[string]any) ([]byte, error) {
	return plist.Marshal(map[string]any{"Header": map[string]any{}, "Request": request}, plist.XMLFormat)
}

// Provision performs one start and finish exchange for a fresh random machine
// identity. The caller supplies the HTTP client (including verified TLS roots).
// It never sends an Apple account username, password or signing resource.
func Provision(ctx context.Context, client *http.Client) (*State, error) {
	if client == nil {
		client = http.DefaultClient
	}
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, err
	}
	identity[6] = identity[6]&15 | 0x40
	identity[8] = identity[8]&63 | 0x80
	text := strings.ToUpper(hex.EncodeToString(identity[:]))
	device := text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
	local := sha256.Sum256(identity[:])
	s := &State{Version: 1, DeviceID: device, LocalUser: strings.ToUpper(hex.EncodeToString(local[:])), Routing: "17106176"}
	lookup, err := request(ctx, client, s, http.MethodGet, lookupURL, nil, "machine URL lookup")
	if err != nil {
		return nil, err
	}
	urls, ok := lookup["urls"].(map[string]any)
	if !ok {
		return nil, errors.New("machine URL lookup lacks URLs")
	}
	startURL, ok1 := urls["midStartProvisioning"].(string)
	finishURL, ok2 := urls["midFinishProvisioning"].(string)
	if !ok1 || !ok2 || !approvedURL(startURL) || !approvedURL(finishURL) {
		return nil, errors.New("invalid machine provisioning URLs")
	}
	body, err := payload(map[string]any{})
	if err != nil {
		return nil, err
	}
	start, err := request(ctx, client, s, http.MethodPost, startURL, body, "machine start")
	if err != nil {
		return nil, err
	}
	response, ok := start["Response"].(map[string]any)
	if !ok {
		return nil, errors.New("machine start lacks response")
	}
	spim, err := packetField(response, "spim")
	if err != nil {
		return nil, err
	}
	var androidIdentity [16]byte
	copy(androidIdentity[:], device[:16])
	session, cpim, err := adimath.NewAndroidProvisioning(spim, androidIdentity, uint32(time.Now().Unix()))
	if err != nil {
		return nil, fmt.Errorf("pure-Go machine start: %w", err)
	}
	body, err = payload(map[string]any{"cpim": base64.StdEncoding.EncodeToString(cpim[:])})
	if err != nil {
		return nil, err
	}
	finish, err := request(ctx, client, s, http.MethodPost, finishURL, body, "machine finish")
	if err != nil {
		return nil, err
	}
	response, ok = finish["Response"].(map[string]any)
	if !ok {
		return nil, errors.New("machine finish lacks response")
	}
	ptm, err := packetField(response, "ptm")
	if err != nil {
		return nil, err
	}
	rawTK, err := packetField(response, "tk")
	if err != nil {
		return nil, err
	}
	if len(rawTK) != 16 {
		return nil, errors.New("invalid machine TK length")
	}
	var tk [16]byte
	copy(tk[:], rawTK)
	defer clear(rawTK)
	s.Machine, err = adimath.FinishAndroidProvisioning(session, ptm, tk)
	if err != nil {
		return nil, fmt.Errorf("pure-Go machine finish: %w", err)
	}
	if routing, ok := response["X-Apple-I-MD-RINFO"]; ok {
		switch value := routing.(type) {
		case string:
			s.Routing = value
		case uint64:
			s.Routing = strconv.FormatUint(value, 10)
		case int64:
			s.Routing = strconv.FormatInt(value, 10)
		default:
			return nil, errors.New("invalid server routing information")
		}
	}
	if _, err = s.Headers(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
