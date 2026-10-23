//go:build !ios

package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"image/png"
	"ipa-loader/app/internal/ipa"
	"os"
	"path/filepath"
	"testing"
)

func extensionPreview() *ipa.Info {
	return &ipa.Info{Name: "YouTube", BundleID: "com.google.ios.youtube", Version: "21.39.4", Build: "21.39.4", Extensions: []ipa.Extension{
		{Name: "Safari", BundleID: "com.google.ios.youtube.safari", Point: "com.apple.Safari.web-extension"},
		{Name: "App Migration", BundleID: "com.google.ios.youtube.migration", Point: "com.apple.app-migration"},
	}}
}

func TestDesktopExtensionReviewRestoresChoicesAndUpdatesCost(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	w := a.NewWindow("extensions")
	defer w.Close()
	s := NewPreview(w, "ready")
	s.services.ExtensionSelection = func(_, _, _ string) (*ipa.ExtensionSelection, error) {
		return &ipa.ExtensionSelection{Included: []string{"com.google.ios.youtube.safari"}}, nil
	}
	s.showIPA(extensionPreview())
	w.Resize(fyne.NewSize(520, 500))
	w.Show()
	if len(s.extensionChecks) != 2 || !s.extensionChecks[0].Checked || s.extensionChecks[1].Checked || s.extensionCost.Text != "2 App IDs" {
		t.Fatal("saved selection was not shown")
	}
	s.sideload()
	if s.extensionDialog == nil || s.busy {
		t.Fatal("installation started before extension review")
	}
	s.extensionChecks[0].SetChecked(false)
	if s.extensionCost.Text != "1 App ID" || len(s.selected.SelectedExtensions().Included) != 0 {
		t.Fatal("all-off selection or cost lost")
	}
	s.extensionChecks[1].SetChecked(true)
	if s.extensionCost.Text != "2 App IDs" || s.selected.SelectedExtensions().Included[0] != "com.google.ios.youtube.migration" {
		t.Fatal("selected extension identity lost")
	}
	s.extensionDialog.Hide()
	s.extensionDialog = nil
	s.setBusy(true)
	for _, check := range s.extensionChecks {
		if !check.Disabled() {
			t.Fatal("extension choice can change during installation")
		}
	}
}

func TestDesktopExtensionReviewSnapshot(t *testing.T) {
	dir := os.Getenv("IPA_LOADER_EXTENSION_REVIEW")
	if dir == "" {
		t.Skip("optional extension review screenshot")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	w := a.NewWindow("Install App")
	defer w.Close()
	s := NewPreview(w, "ready")
	s.showIPA(extensionPreview())
	w.Resize(fyne.NewSize(600, 620))
	w.Show()
	s.sideload()
	s.root.Refresh()
	f, err := os.Create(filepath.Join(dir, "desktop-extensions.png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = png.Encode(f, w.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}
