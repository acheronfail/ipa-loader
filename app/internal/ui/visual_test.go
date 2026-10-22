package ui

import (
	"fmt"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"ipa-loader/app/internal/ipa"
)

func TestLoadedIPALayoutKeepsControlsInsideCard(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	w := a.NewWindow("layout regression")
	defer w.Close()
	s := NewPreview(w, "empty")
	w.Show()
	for _, width := range []float32{520, 600, 800} {
		w.Resize(fyne.NewSize(width, 520))
		s.showIPA(&ipa.Info{Name: strings.Repeat("Long app name ", 8), Version: "2026.10.21", Build: "12345", BundleID: "org.example." + strings.Repeat("long.", 12) + "app"})
		s.root.Refresh()
		panel := a.Driver().AbsolutePositionForObject(s.appPanel)
		for _, child := range []fyne.CanvasObject{s.icon, s.appName, s.appDetail, s.choose} {
			position := a.Driver().AbsolutePositionForObject(child)
			if position.X < panel.X || position.Y < panel.Y || position.X+child.Size().Width > panel.X+s.appPanel.Size().Width+1 || position.Y+child.Size().Height > panel.Y+s.appPanel.Size().Height+1 {
				t.Fatal("selected app content escaped its card")
			}
		}
		if w.Canvas().Size().Width > width+1 {
			t.Fatal("long metadata forced a wider window")
		}
	}
}

func TestProgressDialogKeepsActionsVisible(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("progress regression")
	defer w.Close()
	s := NewPreview(w, "progress")
	w.Resize(fyne.NewSize(520, 480))
	s.resizeOperation()
	w.Show()
	s.root.Refresh()
	for _, child := range []fyne.CanvasObject{s.operationStatus, s.progress, s.cancelButton, s.showActivity} {
		p := a.Driver().AbsolutePositionForObject(child)
		if !child.Visible() || p.Y < 0 || p.Y+child.Size().Height > w.Canvas().Size().Height+1 {
			t.Fatal("progress control fell outside the window")
		}
	}
	s.toggleActivity()
	if !s.activityScroll.Visible() {
		t.Fatal("details did not expand")
	}
	s.toggleActivity()
	if s.activityScroll.Visible() {
		t.Fatal("details did not collapse")
	}
}

func TestDefaultWindowKeepsDeviceDetailsVisible(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	for _, state := range []string{"ready", "accounts", "progress", "error", "success"} {
		w := a.NewWindow(state)
		s := NewPreview(w, state)
		w.Resize(fyne.NewSize(520, 500))
		w.Show()
		s.root.Refresh()
		body := a.Driver().AbsolutePositionForObject(s.installBody)
		hint := a.Driver().AbsolutePositionForObject(s.deviceHint)
		if hint.Y+s.deviceHint.Size().Height > body.Y+s.installBody.Size().Height+1 {
			t.Errorf("device details clipped in %s state", state)
		}
		w.Close()
	}
}

type reviewTheme struct {
	fyne.Theme
	variant fyne.ThemeVariant
}

func (t reviewTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return t.Theme.Color(name, t.variant)
}

// Explicit visual review harness: no live account data or device operations.
func TestUIReviewSnapshots(t *testing.T) {
	dir := os.Getenv("IPA_LOADER_UI_REVIEW")
	if dir == "" {
		t.Skip("optional UI screenshot review")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	for _, variant := range []fyne.ThemeVariant{theme.VariantDark, theme.VariantLight} {
		a.Settings().SetTheme(reviewTheme{NewTheme(), variant})
		for _, width := range []float32{520, 680} {
			for _, state := range []string{"login", "login-error", "saved-login", "empty", "ready", "accounts", "account-settings", "account-menu", "manage-accounts", "setup", "long", "no-device", "progress", "details", "error", "success"} {
				w := a.NewWindow("UI Review")
				s := NewPreview(w, state)
				height := float32(560)
				if state == "login" || state == "login-error" {
					height = 480
				}
				if state == "saved-login" {
					height = 560
				}
				w.Resize(fyne.NewSize(width, height))
				s.resizeOperation()
				w.Show()
				s.root.Refresh()
				name := fmt.Sprintf("%s-%d-%d.png", state, variant, int(width))
				file, err := os.Create(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				err = png.Encode(file, w.Canvas().Capture())
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
				w.Close()
			}
		}
	}
}
