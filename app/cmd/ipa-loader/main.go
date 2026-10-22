package main

import (
	"fyne.io/fyne/v2/app"
	"ipa-loader/app/internal/ui"
)

func main() {
	if runtimeCommand() || fixtureCommand() || loaderCommand() {
		return
	}
	a := app.NewWithID("org.ipaloader.desktop")
	a.Settings().SetTheme(ui.NewTheme())
	a.SetIcon(ui.ApplicationIcon())
	w := a.NewWindow("IPA Loader")
	screen := ui.New(w, ui.NativeServices())
	screen.Start()
	w.ShowAndRun()
}
