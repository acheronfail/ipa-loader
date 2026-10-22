package mobiledevice

import "errors"

func provisioningProfilePayload(response map[string]any) ([][]byte, error) {
	status, ok := response["Status"].(uint64)
	if !ok || status != 0 {
		return nil, errors.New("The iPhone could not provide provisioning profiles")
	}
	payload, ok := response["Payload"].([]any)
	if !ok || len(payload) > 4096 {
		return nil, errors.New("Invalid provisioning profile list")
	}
	profiles := make([][]byte, 0, len(payload))
	var total int
	for _, value := range payload {
		raw, ok := value.([]byte)
		total += len(raw)
		if !ok || len(raw) == 0 || len(raw) > 16<<20 || total > 64<<20 {
			return nil, errors.New("Invalid provisioning profile data")
		}
		profiles = append(profiles, raw)
	}
	return profiles, nil
}

// ErrProfileInstallRejected is a definitive device response, unlike a lost
// connection after submission, which leaves the result uncertain.
var ErrProfileInstallRejected = errors.New("The iPhone rejected the provisioning profile")

func provisioningInstallResult(response map[string]any) error {
	status, ok := response["Status"].(uint64)
	if !ok {
		return errors.New("The iPhone returned an invalid profile installation response")
	}
	if status != 0 {
		return ErrProfileInstallRejected
	}
	return nil
}
