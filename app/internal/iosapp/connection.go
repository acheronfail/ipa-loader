package iosapp

// Connection guidance follows the installed payload, not the signed-in team.
func connectionFailureMessage(builtin, checkingApps bool) string {
	message := "Couldn’t connect to this iPhone. "
	if checkingApps {
		message = "Couldn’t check this iPhone. Showing saved dates. "
	}
	if builtin {
		message += "Enable Local VPN in Settings."
	} else {
		message += "Connect LocalDevVPN and Wi-Fi. In Connection Settings, use the Device IP shown in LocalDevVPN."
	}
	if checkingApps {
		message += " Pull down to retry."
	}
	return message
}
