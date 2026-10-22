package apple

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

const gsaURL = "https://gsa.apple.com/grandslam/GsService2"
const authURL = "https://gsa.apple.com/auth"
const appID = "com.apple.gs.xcode.auth"
const maxResponse = 4 * 1024 * 1024

var requiredHeaders = []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-MMe-Client-Info", "X-Apple-I-SRL-NO", "X-Apple-I-Client-Time", "X-Apple-Locale", "X-Apple-I-TimeZone"}

func number(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case json.Number:
		v, e := n.Int64()
		if e == nil && int64(int(v)) == v {
			return int(v), true
		}
	case int64:
		if int64(int(n)) == n {
			return int(n), true
		}
	case uint64:
		if n <= uint64(^uint(0)>>1) {
			return int(n), true
		}
	case uint:
		return int(n), uint(int(n)) == n
	case uint32:
		return int(n), true
	case int32:
		return int(n), true
	}
	return 0, false
}
func textField(m map[string]any, k string) (string, error) {
	v, ok := m[k].(string)
	if !ok || v == "" || len(v) > 65536 || strings.ContainsAny(v, "\r\n\x00") {
		return "", failure("Apple returned an invalid text field")
	}
	return v, nil
}
func binaryField(m map[string]any, k string, size int) ([]byte, error) {
	v, ok := m[k].([]byte)
	if !ok || (size >= 0 && len(v) != size) {
		return nil, failure("Apple returned an invalid binary field")
	}
	return v, nil
}
func parsePlist(data []byte) (map[string]any, error) {
	stripped := bytes.TrimSpace(data)
	if bytes.HasPrefix(stripped, []byte("<dict>")) {
		data = append(append([]byte("<plist version=\"1.0\">"), stripped...), []byte("</plist>")...)
	}
	var result map[string]any
	if _, err := plist.Unmarshal(data, &result); err != nil || result == nil {
		return nil, failure("Apple returned an invalid property list")
	}
	return result, nil
}
func cloneHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = v
	}
	return out
}
func (c *Client) headers(ctx context.Context) (map[string]string, error) {
	if c.provider == nil {
		return nil, failure("Local authentication headers are unavailable")
	}
	values, err := c.provider(ctx)
	if err != nil {
		return nil, failure("Local authentication-header generation failed")
	}
	return validateHeaders(values)
}
func fingerprint(headers map[string]string) string {
	return hex.EncodeToString(digest([]byte(headers["X-Apple-I-MD-M"])))[:16]
}
func cpd(headers map[string]string, complete, windowsAuthKit bool) (map[string]any, error) {
	if windowsAuthKit {
		return map[string]any{
			"bootstrap": "true", "icscrec": "true", "pbe": "false", "prkgen": "true", "svct": "iCloud", "loc": "en_US",
			"X-Apple-I-MD": headers["X-Apple-I-MD"], "X-Apple-I-MD-M": headers["X-Apple-I-MD-M"], "X-Mme-Device-Id": headers["X-Mme-Device-Id"],
		}, nil
	}
	routing, err := strconv.ParseInt(headers["X-Apple-I-MD-RINFO"], 10, 64)
	if err != nil {
		return nil, failure("Invalid local routing information")
	}
	out := make(map[string]any, len(headers)+10)
	for k, v := range headers {
		if k != "X-MMe-Client-Info" {
			out[k] = v
		}
	}
	out["X-Apple-I-MD-RINFO"] = routing
	for _, k := range []string{"bootstrap", "pbe", "wpbe", "prkgen", "icscrec"} {
		out[k] = true
	}
	out["svct"] = "iCloud"
	out["loc"] = headers["X-Apple-Locale"]
	out["X-Apple-I-Device-Configuration-Mode"] = "0"
	out["AppleIDClientIdentifier"] = headers["X-Mme-Device-Id"]
	if complete {
		out["ckgen"] = true
	}
	return out, nil
}
func (c *Client) request(ctx context.Context, method, address string, headers map[string]string, body []byte) ([]byte, int, error) {
	return c.requestStage(ctx, stageForEndpoint(method, address), method, address, headers, body)
}

// requestStage adds only a source-defined operation label to failures. Never
// include request URLs, query parameters, payloads, response bodies or headers:
// authentication requests contain passwords, one-time codes and session tokens.
func (c *Client) requestStage(ctx context.Context, stage requestStage, method, address string, headers map[string]string, body []byte) (data []byte, status int, err error) {
	return c.requestStageWithErrorBody(ctx, stage, method, address, headers, body, false)
}

// Only the unified certificate client needs a bounded error body to distinguish
// an explicit quota rejection from an uncertain issuance. Bodies stay private.
func (c *Client) requestStageWithErrorBody(ctx context.Context, stage requestStage, method, address string, headers map[string]string, body []byte, readErrorBody bool) (data []byte, status int, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("During %s: %w", stage.description(), err)
		}
	}()
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") || (u.Hostname() != "gsa.apple.com" && u.Hostname() != "developerservices2.apple.com") {
		return nil, 0, failure("Authentication requires an approved Apple HTTPS destination")
	}
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return nil, 0, failure("Could not create Apple HTTPS request")
	}
	if c.portableAuthKit && (stage == stagePasswordChallenge || stage == stagePasswordProof) {
		req = req.WithContext(context.WithValue(req.Context(), portableSRPContextKey{}, true))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	base := c.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	client := *base
	if c.windowsAuthKit && u.Hostname() == "gsa.apple.com" {
		// Match AltSign's fresh ephemeral GSA session; do not carry a cookie
		// jar between GrandSlam requests or alter developer-service sessions.
		client.Jar = nil
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, failure("Apple request cancelled")
		}
		return nil, 0, failure("Could not complete the verified Apple HTTPS request")
	}
	defer response.Body.Close()
	if (response.StatusCode < 200 || response.StatusCode >= 300) && !readErrorBody {
		return nil, response.StatusCode, httpStatusFailure(response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return nil, 0, failure("Could not read Apple HTTPS response")
	}
	if len(data) > maxResponse {
		return nil, 0, failure("Apple response exceeds the supported size")
	}
	encoding := strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding")))
	if encoding == "gzip" || bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, 0, failure("Apple returned an invalid compressed response")
		}
		defer reader.Close()
		data, err = io.ReadAll(io.LimitReader(reader, maxResponse+1))
		if err != nil {
			return nil, 0, failure("Apple returned an invalid compressed response")
		}
		if len(data) > maxResponse {
			return nil, 0, failure("Apple decompressed response exceeds the supported size")
		}
	} else if encoding != "" && encoding != "identity" {
		return nil, 0, failure("Apple returned an unsupported response encoding")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return data, response.StatusCode, httpStatusFailure(response.StatusCode)
	}
	return data, response.StatusCode, nil
}

func httpStatusFailure(status int) error {
	message := "Apple HTTPS request failed"
	if status == http.StatusServiceUnavailable {
		message = "Apple returned Service Unavailable; try signing in again later"
	}
	return &Error{Message: message, Code: status}
}
func (c *Client) gsa(ctx context.Context, body map[string]any, headers map[string]string) (map[string]any, error) {
	encoded, err := plist.Marshal(map[string]any{"Header": map[string]any{"Version": "1.0.1"}, "Request": body}, plist.XMLFormat)
	if err != nil {
		return nil, failure("Could not encode Apple authentication request")
	}
	h := map[string]string{"Content-Type": "text/x-xml-plist", "Accept": "*/*", "User-Agent": "Xcode"}
	for _, k := range []string{"X-MMe-Client-Info", "X-Apple-I-MD-M", "X-Mme-Device-Id"} {
		h[k] = headers[k]
	}
	if c.windowsAuthKit {
		h["User-Agent"] = windowsAuthenticationUserAgent
		h["Accept"] = "text/x-xml-plist"
		h["X-Apple-App-Info"] = appID
		h["X-Xcode-Version"] = "27.0 (27A5218g)"
		h["Connection"] = "close"
		delete(h, "X-Apple-I-MD-M")
		delete(h, "X-Mme-Device-Id")
	}
	if c.portableAuthKit && (body["o"] == "init" || body["o"] == "complete") {
		h["User-Agent"] = windowsAuthenticationUserAgent
		h["X-MMe-Client-Info"] = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	}
	stage := stageAuthentication
	switch body["o"] {
	case "init":
		stage = stagePasswordChallenge
	case "complete":
		stage = stagePasswordProof
	case "apptokens":
		stage = stageApplicationToken
	}
	data, _, err := c.requestStage(ctx, stage, "POST", gsaURL, h, encoded)
	if err != nil {
		return nil, err
	}
	outer, err := parsePlist(data)
	if err != nil {
		return nil, err
	}
	result, ok := outer["Response"].(map[string]any)
	if !ok {
		return nil, failure("Apple returned an invalid authentication response")
	}
	status, ok := result["Status"].(map[string]any)
	if !ok {
		return nil, failure("Apple returned an invalid authentication status")
	}
	code, ok := number(status["ec"])
	if !ok {
		return nil, failure("Apple returned an invalid authentication status")
	}
	if code != 0 {
		return nil, appleError(code)
	}
	return result, nil
}
func (c *Client) Login(ctx context.Context, username, password string, challenge func(Challenge) (string, error)) (*Session, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || password == "" || strings.ContainsAny(username, "\r\n\x00") {
		return nil, failure("An Apple username and password are required")
	}
	var authenticationHeaders map[string]string
	for attempt := 0; attempt < 2; attempt++ {
		headers := authenticationHeaders
		if headers == nil || !c.windowsAuthKit {
			var err error
			headers, err = c.headers(ctx)
			if err != nil {
				return nil, err
			}
			authenticationHeaders = headers
		}
		identity := fingerprint(headers)
		exchange, err := newSRP(username, nil)
		if err != nil {
			return nil, err
		}
		initialCPD, err := cpd(headers, false, c.windowsAuthKit)
		if err != nil {
			return nil, err
		}
		publicKey := minimum(exchange.A)
		if c.windowsAuthKit {
			publicKey = pad(exchange.A)
		}
		initial, err := c.gsa(ctx, map[string]any{"o": "init", "u": username, "cpd": initialCPD, "ps": []string{"s2k", "s2k_fo"}, "A2k": publicKey}, headers)
		if err != nil {
			return nil, err
		}
		proof, err := exchange.challenge(password, initial)
		if err != nil {
			return nil, err
		}
		continuation, err := textField(initial, "c")
		if err != nil {
			return nil, err
		}
		completeCPD, _ := cpd(headers, true, c.windowsAuthKit)
		complete, err := c.gsa(ctx, map[string]any{"o": "complete", "u": username, "cpd": completeCPD, "M1": proof, "c": continuation}, headers)
		if err != nil {
			return nil, err
		}
		m2, err := binaryField(complete, "M2", 32)
		if err != nil {
			return nil, err
		}
		key, err := exchange.verify(m2)
		if err != nil {
			return nil, err
		}
		encrypted, err := binaryField(complete, "spd", -1)
		if err != nil {
			return nil, err
		}
		spd, err := decryptSPD(key, encrypted)
		clear(key)
		if err != nil {
			return nil, err
		}
		status := complete["Status"].(map[string]any)
		au, validAuthStep := status["au"].(string)
		if status["au"] != nil && !validAuthStep {
			return nil, failure("Apple returned an invalid authentication step")
		}
		hsc, _ := number(status["hsc"])
		if au != "" && au != "trustedDeviceSecondaryAuth" && au != "secondaryAuth" {
			return nil, failure("Complete the additional account step in Apple’s account interface")
		}
		if au == "trustedDeviceSecondaryAuth" || au == "secondaryAuth" || hsc == 409 {
			if attempt > 0 {
				return nil, failure("Apple requested verification again after the allowed login retry")
			}
			method := "trusted"
			if au == "secondaryAuth" {
				method = "sms"
			}
			if err = c.twoFactor(ctx, spd, headers, method, challenge, hsc == 409); err != nil {
				return nil, err
			}
			if c.windowsAuthKit {
				authenticationHeaders, err = c.refreshAuthenticationHeaders(ctx, headers)
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		sk, err := binaryField(spd, "sk", 32)
		if err != nil {
			return nil, err
		}
		nonce, err := binaryField(spd, "c", -1)
		if err != nil {
			return nil, err
		}
		dsid, err := textField(spd, "adsid")
		if err != nil {
			return nil, err
		}
		idms, err := textField(spd, "GsIdmsToken")
		if err != nil {
			return nil, err
		}
		tokenCPD := initialCPD
		if c.windowsAuthKit {
			headers, err = c.refreshAuthenticationHeaders(ctx, headers)
			if err != nil {
				return nil, err
			}
			tokenCPD, err = cpd(headers, false, c.windowsAuthKit)
			if err != nil {
				return nil, err
			}
		}
		tokenResult, err := c.gsa(ctx, map[string]any{"o": "apptokens", "u": dsid, "cpd": tokenCPD, "c": nonce, "app": []string{appID}, "t": idms, "checksum": mac(sk, []byte("apptokens"+dsid+appID))}, headers)
		if err != nil {
			return nil, err
		}
		envelope, err := binaryField(tokenResult, "et", -1)
		if err != nil {
			return nil, err
		}
		tokens, err := decryptToken(sk, envelope)
		if err != nil {
			return nil, err
		}
		tokenMap, ok := tokens["t"].(map[string]any)
		if !ok {
			return nil, failure("Apple returned no Xcode application token")
		}
		entry, ok := tokenMap[appID].(map[string]any)
		if !ok {
			return nil, failure("Apple returned no Xcode application token")
		}
		token, err := textField(entry, "token")
		if err != nil {
			return nil, err
		}
		return &Session{Username: username, DSID: dsid, Token: token, IdentityFP: identity}, nil
	}
	return nil, failure("Apple authentication did not complete")
}

func (c *Client) refreshAuthenticationHeaders(ctx context.Context, previous map[string]string) (map[string]string, error) {
	next, err := c.headers(ctx)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"X-Apple-I-MD-M", "X-Mme-Device-Id", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-MMe-Client-Info", "X-Apple-I-SRL-NO", "X-Apple-Locale", "X-Apple-I-TimeZone"} {
		if previous[name] != next[name] {
			return nil, failure("Local authentication identity changed during sign-in")
		}
	}
	return next, nil
}
func requestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", failure("Could not generate developer request identifier")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return strings.ToUpper(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]), nil
}
func (c *Client) Request(ctx context.Context, session *Session, action string, params map[string]any, teamID string) (map[string]any, error) {
	result, err := c.developerRequest(ctx, session, action, params, teamID, false)
	var quota *Error
	if action == "submitDevelopmentCSR" && errors.As(err, &quota) && quota.Code == 7460 {
		// The legacy endpoint explicitly refused issuance. Try the unified
		// certificate API once with the very same retained CSR, never another
		// key or automatic certificate revocation. An uncertain unified result
		// stays uncertain in the caller's durable submission journal.
		csr, _ := params["csrContent"].(string)
		return c.submitUnifiedDevelopmentCSR(ctx, session, teamID, csr)
	}
	return result, err
}

// Revocation is available only through the explicit, revalidated single-
// certificate method. Generic provisioning callers cannot invoke it.
func (c *Client) developerRequest(ctx context.Context, session *Session, action string, params map[string]any, teamID string, allowCertificateRevocation bool) (map[string]any, error) {
	allowed := map[string]bool{"listTeams": true, "listDevices": true, "addDevice": true, "listAppIds": true, "addAppId": true, "listAllDevelopmentCerts": true, "submitDevelopmentCSR": true, "downloadTeamProvisioningProfile": true}
	for _, operation := range []string{"listApplicationGroups", "addApplicationGroup", "assignApplicationGroupToAppId", "updateAppId"} {
		allowed[operation] = true
	}
	if !allowed[action] && !(allowCertificateRevocation && action == "revokeDevelopmentCert") {
		return nil, failure("Unsupported developer operation")
	}
	for _, k := range []string{"clientId", "protocolVersion", "requestId", "teamId"} {
		if _, ok := params[k]; ok {
			return nil, failure("Invalid developer operation parameters")
		}
	}
	if action != "listTeams" {
		if teamID == "" {
			return nil, failure("A valid developer team is required")
		}
		for _, v := range teamID {
			if !(v >= 'A' && v <= 'Z' || v >= 'a' && v <= 'z' || v >= '0' && v <= '9') {
				return nil, failure("A valid developer team is required")
			}
		}
	}
	headers, err := c.developerHeaders(ctx, session)
	if err != nil {
		return nil, err
	}
	id, err := requestID()
	if err != nil {
		return nil, err
	}
	body := map[string]any{"clientId": "XABBG36SBA", "protocolVersion": "QH65B2", "requestId": id}
	for k, v := range params {
		body[k] = v
	}
	suffix := ""
	if action != "listTeams" {
		body["teamId"] = teamID
		body["DTDK_Platform"] = "ios"
		suffix = "ios/"
	}
	encoded, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return nil, failure("Could not encode developer request")
	}
	stage := stageProvisioning
	if action == "listTeams" {
		stage = stageTeamLookup
	}
	data, _, err := c.requestStage(ctx, stage, "POST", "https://developerservices2.apple.com/services/QH65B2/"+suffix+action+".action?clientId=XABBG36SBA", headers, encoded)
	if err != nil {
		return nil, err
	}
	result, err := parsePlist(data)
	if err != nil {
		return nil, err
	}
	code, ok := number(result["resultCode"])
	if !ok {
		return nil, failure("Apple returned an invalid developer status")
	}
	if code != 0 {
		return nil, appleError(code)
	}
	return result, nil
}
func (c *Client) Teams(ctx context.Context, session *Session) ([]Team, error) {
	result, err := c.Request(ctx, session, "listTeams", nil, "")
	if err != nil {
		return nil, err
	}
	records, ok := result["teams"].([]any)
	if !ok {
		return nil, failure("Apple returned an invalid team list")
	}
	teams := make([]Team, 0, len(records))
	for _, value := range records {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, failure("Apple returned an invalid team record")
		}
		id, err := textField(record, "teamId")
		if err != nil {
			return nil, err
		}
		name, err := textField(record, "name")
		if err != nil {
			return nil, err
		}
		team := Team{ID: id, Name: name}
		team.AppIDsUnlimited, team.LimitKnown, team.AppIDLimit = teamQuota(record, time.Now())
		teams = append(teams, team)
	}
	return teams, nil
}

// The free ten-ID/rolling-seven-day rule does not apply to a demonstrably
// current paid Apple Developer Program membership. Missing/ambiguous metadata
// stays unknown; organization type alone does not prove a current membership.
func teamQuota(record map[string]any, now time.Time) (unlimited, known bool, limit int) {
	free, explicit := record["xcodeFreeOnly"].(bool)
	if !explicit {
		return false, false, 0
	}
	if free {
		return false, true, 10
	}
	memberships, ok := record["memberships"].([]any)
	if !ok {
		return false, false, 0
	}
	for _, value := range memberships {
		member, ok := value.(map[string]any)
		if !ok {
			continue
		}
		name, _ := member["name"].(string)
		status, _ := member["status"].(string)
		if !strings.EqualFold(strings.TrimSpace(name), "Apple Developer Program") || !strings.EqualFold(strings.TrimSpace(status), "active") {
			continue
		}
		start, startOK := membershipDate(member["dateStart"])
		expiry, expiryOK := membershipDate(member["dateExpire"])
		if startOK && expiryOK && !now.Before(start) && now.Before(expiry) {
			return true, true, 0
		}
	}
	return false, false, 0
}
func membershipDate(value any) (time.Time, bool) {
	switch v := value.(type) {
	case time.Time:
		return v, !v.IsZero()
	case string:
		t, e := time.Parse(time.RFC3339, v)
		return t, e == nil && !t.IsZero()
	}
	return time.Time{}, false
}

// developerHeaders applies the same identity and credential guards to both
// legacy plist operations and the unified-certificate JSON endpoint.
func (c *Client) developerHeaders(ctx context.Context, session *Session) (map[string]string, error) {
	if session == nil || session.DSID == "" || session.Token == "" || strings.ContainsAny(session.DSID+session.Token, "\r\n\x00") {
		return nil, failure("A valid Apple session is required")
	}
	headers, err := c.headers(ctx)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(session.IdentityFP), []byte(fingerprint(headers))) {
		return nil, failure("Local authentication identity changed; sign in again")
	}
	for k, v := range map[string]string{"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist", "User-Agent": "Xcode", "X-Apple-App-Info": appID, "X-Xcode-Version": "11.2 (11B52)", "X-Apple-I-Identity-Id": session.DSID, "X-Apple-GS-Token": session.Token} {
		headers[k] = v
	}
	return headers, nil
}
