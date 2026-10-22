package platform

import "fmt"

// A phone can change state after this check. This gate avoids portal mutations
// when it is already locked; installation still needs independent confirmation.
func validateLockState(state map[string]any) error {
	required, ok := state["passcodeRequired"].(bool)
	if !ok {
		return failure("The iPhone did not report its lock state; unlock it and try again")
	}
	if required {
		return failure("Unlock your iPhone, keep it awake, and try again")
	}
	return nil
}

func (e *engine) checkDeviceUnlocked(device Device) error {
	state, err := e.deviceJSON("device-lock-state", "device", "info", "lockState", "--device", device.ID)
	if err != nil {
		return fmt.Errorf("Could not check the iPhone; reconnect it, unlock it, then try again: %w", err)
	}
	return validateLockState(state)
}
