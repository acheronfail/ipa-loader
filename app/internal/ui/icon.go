//go:build !ios

package ui

import (
	"bytes"
	"image"
	"image/png"
	"sync"

	"fyne.io/fyne/v2"
	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
)

// Give the native Dock a bitmap so its SVG conversion cannot change the mask
// or transparent margins. Render at intrinsic resolution, as the ICNS builder does.
var macDockIcon = sync.OnceValue(func() fyne.Resource {
	master := image.NewRGBA(image.Rect(0, 0, 1024, 1024))
	icon, err := oksvg.ReadIconStream(bytes.NewReader(MacIcon.Content()))
	if err != nil {
		panic(err)
	}
	icon.Draw(rasterx.NewDasher(1024, 1024, rasterx.NewScannerGV(1024, 1024, master, master.Bounds())), 1)
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, master); err != nil {
		panic(err)
	}
	return fyne.NewStaticResource("ipa-loader-macos.png", encoded.Bytes())
})
