//go:build !darwin || !cgo

package ui

import (
	"errors"
	"fyne.io/fyne/v2"
	"github.com/ncruces/zenity"
)

// The blocking OS chooser runs on a worker; all Fyne updates stay on its event
// goroutine. Cancellation returns no selection and leaves the current IPA alone.
func nativeIPAFile(_ fyne.Window, current string) (string, error) {
	options := []zenity.Option{zenity.Title("Choose an IPA"), zenity.FileFilter{Name: "iPhone apps", Patterns: []string{"*.ipa"}, CaseFold: true}}
	if current != "" {
		options = append(options, zenity.Filename(current))
	}
	path, err := zenity.SelectFile(options...)
	if errors.Is(err, zenity.ErrCanceled) {
		return "", nil
	}
	if err != nil {
		return "", errors.New("The system file picker could not be opened. You can also drag an IPA into this window")
	}
	return path, nil
}
