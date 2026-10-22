package apple

// These labels identify protocol stages without exposing endpoint addresses or
// any user-controlled operation text. An unknown stage always uses a constant.
type requestStage uint8

const (
	stageAuthentication requestStage = iota
	stagePasswordChallenge
	stagePasswordProof
	stageApplicationToken
	stageTrustedDelivery
	stageTrustedValidation
	stagePhoneLookup
	stageSMSDelivery
	stageSMSValidation
	stageTeamLookup
	stageProvisioning
)

func (s requestStage) description() string {
	switch s {
	case stagePasswordChallenge:
		return "Apple password challenge"
	case stagePasswordProof:
		return "Apple password proof"
	case stageApplicationToken:
		return "Apple application-token exchange"
	case stageTrustedDelivery:
		return "trusted-device code delivery"
	case stageTrustedValidation:
		return "trusted-device code validation"
	case stagePhoneLookup:
		return "trusted-phone lookup"
	case stageSMSDelivery:
		return "SMS code delivery"
	case stageSMSValidation:
		return "SMS code validation"
	case stageTeamLookup:
		return "developer-team lookup"
	case stageProvisioning:
		return "developer provisioning"
	default:
		return "Apple authentication"
	}
}

func stageForEndpoint(method, address string) requestStage {
	switch {
	case method == "GET" && address == authURL+"/verify/trusteddevice":
		return stageTrustedDelivery
	case method == "GET" && address == gsaURL+"/validate":
		return stageTrustedValidation
	case method == "GET" && address == authURL:
		return stagePhoneLookup
	case method == "PUT" && address == authURL+"/verify/phone":
		return stageSMSDelivery
	case method == "POST" && address == authURL+"/verify/phone/securitycode":
		return stageSMSValidation
	case method == "POST" && address == "https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA":
		return stageTeamLookup
	}
	// Developer operations are already checked against the Request action
	// allowlist. Use a generic constant label for all remaining destinations.
	return stageAuthentication
}
