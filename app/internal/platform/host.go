package platform

import "ipa-loader/app/internal/apple"

// The provisioning, bundle identity, signing graph and recovery controller are
// shared. Host providers supply only native credential/tool/device operations.
type hostBackend interface {
	deviceJSON(*engine, string, ...string) (map[string]any, error)
	identities(*engine) (map[string]bool, error)
	createIdentity(*engine, requestClient, *apple.Session, string, []map[string]any) (string, error)
	signApp(*engine, appInfo, string, string) error
	checkTools(*engine) error
	sharingLibrary(*engine) (string, error)
	install(*engine, appInfo, Device, *Result, func(float64, string)) error
}

func (e *engine) checkInstallDevice(device Device) error {
	if e.host == nil {
		return failure("Application host is not configured")
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if device.Transport != "USB" && device.Transport != "WiFi" {
		return failure("Select a connected USB or Wi-Fi iPhone")
	}
	if !validText(device.UDID) {
		return failure("The selected iPhone has no valid hardware identifier")
	}
	_, release, err := e.openStagingRegistry(device)
	if err != nil {
		return err
	}
	release()
	return nil
}
