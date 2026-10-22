package apple

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DevelopmentCertificate is a public certificate summary. It contains no key
// or account credential. SHA256 binds a user's selection to the exact DER.
type DevelopmentCertificate struct {
	Serial, Name, Kind, SHA256 string
	IssuedAt, ExpiresAt        time.Time
	portalID                   string
}

// Xcode's unified certificate creation request. The host has already retained
// the key and marked submission before calling Request. A successful response
// must contain an issued certificate for that exact public key and team.
func (c *Client) submitUnifiedDevelopmentCSR(ctx context.Context, session *Session, team, csrPEM string) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(csrPEM) > 16<<10 {
		return nil, failure("Retained signing request is too large")
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, failure("Retained signing request is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, failure("Retained signing request is invalid")
	}
	key, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 2048 {
		return nil, failure("Retained signing request has an unsupported key")
	}
	headers, err := c.developerHeaders(ctx, session)
	if err != nil {
		return nil, err
	}
	headers["Content-Type"], headers["Accept"] = "application/vnd.api+json", "application/vnd.api+json"
	body, err := json.Marshal(map[string]any{"data": map[string]any{"type": "certificates", "attributes": map[string]string{"certificateType": "DEVELOPMENT", "csrContent": csrPEM, "teamId": team}}})
	if err != nil {
		return nil, failure("Could not encode unified signing request")
	}
	response, status, err := c.requestStageWithErrorBody(ctx, stageProvisioning, "POST", "https://developerservices2.apple.com/services/v1/certificates", headers, body, true)
	if err != nil {
		if status == 409 && unifiedCertificateQuota(response) {
			return nil, appleError(7460)
		}
		return nil, fmt.Errorf("Unified signing request was not confirmed; the retained key will be checked before another submission: %w", err)
	}
	var result struct {
		Data struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			Attributes struct {
				Content []byte `json:"certificateContent"`
			} `json:"attributes"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(response, &result) != nil || len(result.Errors) != 0 || result.Data.Type != "certificates" || result.Data.ID == "" || len(result.Data.Attributes.Content) > 64<<10 {
		return nil, failure("Apple returned an invalid unified signing response; the retained key will be checked before another submission")
	}
	certificate, err := x509.ParseCertificate(result.Data.Attributes.Content)
	if err != nil || !bytes.Equal(certificate.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, failure("Apple's unified certificate does not match the retained signing request")
	}
	belongs := false
	for _, unit := range certificate.Subject.OrganizationalUnit {
		if unit == team {
			belongs = true
		}
	}
	if !belongs {
		return nil, failure("Apple's unified certificate belongs to a different team")
	}
	return map[string]any{"certRequest": map[string]any{"serialNum": strings.ToUpper(certificate.SerialNumber.Text(16))}}, nil
}

func unifiedCertificateQuota(body []byte) bool {
	var response struct {
		Errors []struct{ Code, Detail string } `json:"errors"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Errors) != 1 {
		return false
	}
	item := response.Errors[0]
	detail := strings.TrimSuffix(strings.Join(strings.Fields(strings.ToLower(item.Detail)), " "), ".")
	return item.Code == "ENTITY_ERROR" && (detail == "you already have a current development certificate or a pending certificate request" || detail == "you already have a current ios development certificate or a pending certificate request")
}

// DevelopmentCertificates lists active certificates for an explicit team.
// It never chooses a certificate to revoke or modifies the account.
func (c *Client) DevelopmentCertificates(ctx context.Context, session *Session, team string) ([]DevelopmentCertificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := c.Request(ctx, session, "listAllDevelopmentCerts", nil, team)
	if err != nil {
		return nil, err
	}
	list, ok := response["certificates"].([]any)
	if !ok || len(list) > 1000 {
		return nil, failure("Apple returned an invalid development certificate list")
	}
	result := make([]DevelopmentCertificate, 0, len(list))
	seen := map[string]bool{}
	for _, item := range list {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, failure("Apple returned an invalid development certificate")
		}
		status, _ := record["status"].(string)
		if record["revoked"] == true || strings.EqualFold(status, "revoked") {
			continue
		}
		der, ok := record["certContent"].([]byte)
		if !ok || len(der) == 0 || len(der) > 64<<10 {
			return nil, failure("Apple returned an invalid development certificate")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil || cert.SerialNumber.Sign() <= 0 {
			return nil, failure("Apple returned an invalid development certificate")
		}
		belongs := false
		for _, unit := range cert.Subject.OrganizationalUnit {
			if unit == team {
				belongs = true
			}
		}
		if !belongs {
			return nil, failure("Development certificate belongs to a different team")
		}
		if !time.Now().Before(cert.NotAfter) {
			continue
		}
		serial := strings.ToUpper(cert.SerialNumber.Text(16))
		if seen[serial] {
			return nil, failure("Apple returned ambiguous development certificates")
		}
		seen[serial] = true
		name, _ := record["machineName"].(string)
		if name == "" {
			name = cert.Subject.CommonName
		}
		if name == "" {
			name = "Development certificate"
		}
		if len(name) > 512 || strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return nil, failure("Apple returned an invalid certificate name")
		}
		sum := sha256.Sum256(der)
		kind := "Development"
		switch {
		case strings.HasPrefix(cert.Subject.CommonName, "iPhone Developer:"):
			kind = "iOS Development"
		case strings.HasPrefix(cert.Subject.CommonName, "Mac Developer:"):
			kind = "Mac Development"
		case strings.HasPrefix(cert.Subject.CommonName, "Apple Development:"):
			kind = "Apple Development"
		}
		portalID, _ := record["certificateId"].(string)
		result = append(result, DevelopmentCertificate{Serial: serial, Name: name, Kind: kind, SHA256: hex.EncodeToString(sum[:]), IssuedAt: cert.NotBefore, ExpiresAt: cert.NotAfter, portalID: portalID})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IssuedAt.Equal(result[j].IssuedAt) {
			return result[i].Serial < result[j].Serial
		}
		return result[i].IssuedAt.Before(result[j].IssuedAt)
	})
	return result, nil
}

// RevokeDevelopmentCertificate revokes exactly one explicitly selected public
// certificate after checking a fresh inventory. Callers must first obtain the
// user's confirmation: provisioning profiles containing it become invalid.
// It never retries a revocation or selects a different certificate on failure.
func (c *Client) RevokeDevelopmentCertificate(ctx context.Context, session *Session, team string, selected DevelopmentCertificate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	serial, err := hex.DecodeString(selected.Serial)
	if err != nil && len(selected.Serial)%2 == 1 {
		serial, err = hex.DecodeString("0" + selected.Serial)
	}
	digest, digestErr := hex.DecodeString(selected.SHA256)
	if err != nil || len(serial) == 0 || len(serial) > 32 || digestErr != nil || len(digest) != sha256.Size {
		return failure("Select a certificate from the current development certificate list")
	}
	certificates, err := c.DevelopmentCertificates(ctx, session, team)
	if err != nil {
		return err
	}
	var target *DevelopmentCertificate
	for i := range certificates {
		if certificates[i].Serial == selected.Serial && certificates[i].SHA256 == selected.SHA256 {
			target = &certificates[i]
		}
	}
	if target == nil {
		return failure("The selected development certificate changed or is no longer active; refresh the list")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if target.Kind == "Apple Development" {
		err = c.revokeUnifiedDevelopmentCertificate(ctx, session, team, target.portalID)
	} else {
		_, err = c.developerRequest(ctx, session, "revokeDevelopmentCert", map[string]any{"serialNumber": target.Serial}, team, true)
	}
	if err != nil {
		return fmt.Errorf("Certificate revocation was not confirmed; refresh the list before retrying: %w", err)
	}
	remaining, err := c.DevelopmentCertificates(ctx, session, team)
	if err != nil {
		return fmt.Errorf("Apple accepted certificate revocation, but its result could not be verified; refresh the list: %w", err)
	}
	for _, cert := range remaining {
		if cert.Serial == target.Serial {
			return failure("Apple accepted certificate revocation, but the certificate is still listed; refresh the list before retrying")
		}
	}
	return nil
}

// Unified Apple Development certificates are not handled by the legacy iOS
// endpoint (7252). Xcode's JSON API uses the freshly listed certificateId,
// never the serial as an ID. Source comparison is recorded in linux-support.md.
func (c *Client) revokeUnifiedDevelopmentCertificate(ctx context.Context, session *Session, team, id string) error {
	if id == "" || len(id) > 128 {
		return failure("Apple did not provide a usable identifier for the selected Apple Development certificate")
	}
	for _, r := range id {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return failure("Apple returned an invalid unified certificate identifier")
		}
	}
	headers, err := c.developerHeaders(ctx, session)
	if err != nil {
		return err
	}
	headers["Content-Type"] = "application/vnd.api+json"
	headers["Accept"] = "application/vnd.api+json"
	headers["X-HTTP-Method-Override"] = "DELETE"
	body, err := json.Marshal(map[string]string{"urlEncodedQueryParams": url.Values{"teamId": []string{team}}.Encode()})
	if err != nil {
		return failure("Could not encode unified certificate revocation")
	}
	response, _, err := c.requestStage(ctx, stageProvisioning, "POST", "https://developerservices2.apple.com/services/v1/certificates/"+id, headers, body)
	if err != nil {
		return err
	}
	if len(response) > 0 {
		var result map[string]json.RawMessage
		if json.Unmarshal(response, &result) != nil {
			return failure("Apple returned an invalid unified certificate response")
		}
		if raw, ok := result["errors"]; ok {
			var failures []json.RawMessage
			if json.Unmarshal(raw, &failures) != nil || len(failures) != 0 {
				return failure("Apple rejected unified certificate revocation")
			}
		}
	}
	return nil
}
