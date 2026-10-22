package platform

func (e *engine) confirmInstalled(app appInfo, device Device, result *Result, notify func(float64, string)) error {
	notify(.98, "Checking installed version and build")
	inventory, err := e.deviceJSON("installed-app", "device", "info", "apps", "--device", device.ID, "--bundle-id", app.BundleID)
	if err != nil {
		return err
	}
	apps, err := recordList(inventory, "apps")
	if err != nil {
		return err
	}
	matches := 0
	for _, a := range apps {
		if stringField(a, "bundleIdentifier") == app.BundleID {
			matches++
			if stringField(a, "version") != app.Version || stringField(a, "bundleVersion") != app.Build {
				return failure("Installed app version or build did not match")
			}
		}
	}
	if matches != 1 {
		return failure("Installed app could not be independently confirmed")
	}
	result.Installed = true
	notify(1, "Installation confirmed")
	return nil
}
