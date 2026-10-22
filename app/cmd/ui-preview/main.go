// Command ui-preview runs the real UI with synthetic state and no Apple/device
// services. It never opens saved accounts or starts a real installation.
package main

import (
	"flag"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"ipa-loader/app/internal/ui"
)

func main() {
	state := flag.String("state", "ready", "login, login-error, saved-login, empty, ready, accounts, account-settings, account-menu, manage-accounts, setup, long, no-device, progress, details, error, success")
	width := flag.Float64("width", 600, "window width")
	height := flag.Float64("height", 560, "window height")
	flag.Parse()
	a := app.NewWithID("org.ipaloader.ui-preview")
	a.Settings().SetTheme(ui.NewTheme())
	a.SetIcon(ui.ApplicationIcon())
	w := a.NewWindow("IPA Loader — UI Preview · " + *state)
	ui.NewPreview(w, *state)
	if *state != "login" && *state != "login-error" && *state != "saved-login" {
		w.Resize(fyne.NewSize(float32(*width), float32(*height)))
	}
	w.ShowAndRun()
}
