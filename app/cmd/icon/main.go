// Command icon creates local bundle assets; it is not part of the application.
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"

	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
	"golang.org/x/image/draw"
	"ipa-loader/app/internal/ui"
)

func main() {
	if len(os.Args) != 2 {
		panic("icon output directory required")
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}
	// Rasterize at the SVG's intrinsic size, then downsample every ICNS variant.
	// This also avoids stroke scaling differences in the legacy SVG renderer.
	master := image.NewRGBA(image.Rect(0, 0, 1024, 1024))
	icon, err := oksvg.ReadIconStream(bytes.NewReader(ui.MacIcon.Content()))
	if err != nil {
		panic(err)
	}
	icon.Draw(rasterx.NewDasher(1024, 1024, rasterx.NewScannerGV(1024, 1024, master, master.Bounds())), 1)
	for _, base := range []int{16, 32, 128, 256, 512} {
		for _, scale := range []int{1, 2} {
			size := base * scale
			img := image.NewRGBA(image.Rect(0, 0, size, size))
			draw.CatmullRom.Scale(img, img.Bounds(), master, master.Bounds(), draw.Src, nil)
			name := fmt.Sprintf("icon_%dx%d", base, base)
			if scale == 2 {
				name += "@2x"
			}
			f, err := os.Create(filepath.Join(dir, name+".png"))
			if err != nil {
				panic(err)
			}
			err = png.Encode(f, img)
			f.Close()
			if err != nil {
				panic(err)
			}
		}
	}
}
