package apple

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

func ask(challenge func(Challenge) (string, error), value Challenge) (string, error) {
	if challenge == nil {
		return "", failure("Apple verification requires interaction")
	}
	answer, err := challenge(value)
	if err != nil {
		return "", failure("Apple verification cancelled")
	}
	return answer, nil
}
func codeValid(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func jsonObject(data []byte) (map[string]any, error) {
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, failure("Apple returned an invalid verification response")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, failure("Apple returned an invalid verification response")
	}
	return result, nil
}

func (c *Client) refreshVerificationHeaders(ctx context.Context, identity, headers map[string]string) error {
	if !c.windowsAuthKit {
		return nil
	}
	fresh, err := c.refreshAuthenticationHeaders(ctx, identity)
	if err != nil {
		return err
	}
	for _, name := range requiredHeaders {
		if value, ok := fresh[name]; ok {
			headers[name] = value
		}
	}
	delete(headers, "X-Apple-I-SRL-NO")
	return nil
}
func (c *Client) twoFactor(ctx context.Context, spd map[string]any, anisette map[string]string, method string, challenge func(Challenge) (string, error), alreadySent bool) error {
	dsid, err := textField(spd, "adsid")
	if err != nil {
		return err
	}
	idms, err := textField(spd, "GsIdmsToken")
	if err != nil {
		return err
	}
	headers := cloneHeaders(anisette)
	headers["X-Apple-Identity-Token"] = base64.StdEncoding.EncodeToString([]byte(dsid + ":" + idms))
	headers["User-Agent"] = "Xcode"
	headers["X-Apple-App-Info"] = appID
	headers["X-Xcode-Version"] = "11.2 (11B52)"
	if c.windowsAuthKit {
		headers["User-Agent"] = windowsAuthenticationUserAgent
		headers["X-Xcode-Version"] = "27.0 (27A5218g)"
		headers["Connection"] = "close"
		delete(headers, "X-Apple-I-SRL-NO")
	}
	if c.portableAuthKit {
		headers["User-Agent"] = windowsAuthenticationUserAgent
	}
	headers["Accept-Language"] = "en-us"
	if method == "trusted" {
		headers["Content-Type"] = "text/x-xml-plist"
		headers["Accept"] = "text/x-xml-plist"
		if !alreadySent {
			if _, _, err = c.request(ctx, "GET", authURL+"/verify/trusteddevice", headers, nil); err != nil {
				return err
			}
		}
		code, err := ask(challenge, Challenge{Kind: "trusted", Message: "Enter the six-digit code shown on your trusted Apple device."})
		if err != nil {
			return err
		}
		if !codeValid(code) {
			return failure("Verification code must contain six digits")
		}
		headers["security-code"] = code
		if err = c.refreshVerificationHeaders(ctx, anisette, headers); err != nil {
			return err
		}
		data, _, err := c.request(ctx, "GET", gsaURL+"/validate", headers, nil)
		if err != nil {
			return err
		}
		result, err := parsePlist(data)
		if err != nil {
			return err
		}
		value, exists := result["ec"]
		if !exists {
			nested, ok := result["Status"].(map[string]any)
			if !ok {
				return failure("Apple returned an invalid verification status")
			}
			value = nested["ec"]
		}
		status, ok := number(value)
		if !ok {
			return failure("Apple returned an invalid verification status")
		}
		if status != 0 {
			return appleError(status)
		}
		return nil
	}
	headers["Content-Type"] = "application/json"
	headers["Accept"] = "application/json"
	data, status, err := c.request(ctx, "GET", authURL, headers, nil)
	if err != nil {
		return err
	}
	extras, err := jsonObject(data)
	if err != nil {
		return err
	}
	values, ok := extras["trustedPhoneNumbers"].([]any)
	if !ok || len(values) == 0 {
		return failure("Apple returned no supported trusted phone")
	}
	phones := make([]Phone, 0, len(values))
	for _, value := range values {
		phone, ok := value.(map[string]any)
		if !ok {
			return failure("Apple returned invalid trusted-phone metadata")
		}
		id, ok := number(phone["id"])
		if !ok || id < 0 {
			return failure("Apple returned invalid trusted-phone metadata")
		}
		label, _ := phone["numberWithDialCode"].(string)
		if label == "" {
			label, _ = phone["number"].(string)
		}
		if label == "" {
			label = fmt.Sprintf("Trusted phone %d", id)
		}
		phones = append(phones, Phone{ID: id, Label: label})
	}
	selected := phones[0].ID
	if len(phones) > 1 {
		answer, err := ask(challenge, Challenge{Kind: "phone", Message: "Choose a trusted phone for the verification code.", Phones: phones})
		if err != nil {
			return err
		}
		selected, err = strconv.Atoi(answer)
		if err != nil {
			return failure("Invalid trusted-phone selection")
		}
		found := false
		for _, phone := range phones {
			if selected == phone.ID {
				found = true
			}
		}
		if !found {
			return failure("Invalid trusted-phone selection")
		}
	}
	body := map[string]any{"phoneNumber": map[string]any{"id": selected}, "mode": "sms"}
	if status != 201 && !alreadySent {
		encoded, _ := json.Marshal(body)
		if _, _, err = c.request(ctx, "PUT", authURL+"/verify/phone", headers, encoded); err != nil {
			return err
		}
	}
	code, err := ask(challenge, Challenge{Kind: "sms", Message: "Enter the six-digit code sent to your trusted phone."})
	if err != nil {
		return err
	}
	if !codeValid(code) {
		return failure("Verification code must contain six digits")
	}
	if err = c.refreshVerificationHeaders(ctx, anisette, headers); err != nil {
		return err
	}
	body["securityCode"] = map[string]any{"code": code}
	encoded, _ := json.Marshal(body)
	data, _, err = c.request(ctx, "POST", authURL+"/verify/phone/securitycode", headers, encoded)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		result, err := jsonObject(data)
		if err != nil {
			return err
		}
		if errors, exists := result["serviceErrors"]; exists && errors != nil {
			if list, ok := errors.([]any); !ok || len(list) > 0 {
				return failure("Apple rejected the SMS verification code")
			}
		}
	}
	return nil
}
