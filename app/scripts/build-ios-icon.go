//go:build ignore

// Build opaque iOS icons from the application's existing vector brand.
//
package main

import (
	"bytes"
	"fmt"
	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
	"image"
	"image/color"
	"image/png"
	"ipa-loader/app/internal/ui"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		panic("iOS app directory required")
	}
	for _, size := range []int{120, 152, 167, 180, 1024} {
		img := image.NewRGBA(image.Rect(0, 0, size, size))
		for y := 0; y < size; y++ {
			for x := 0; x < size; x++ {
				img.SetRGBA(x, y, color.RGBA{8, 127, 140, 255})
			}
		}
		icon, err := oksvg.ReadIconStream(bytes.NewReader(ui.Brand.Content()))
		if err != nil {
			panic(err)
		}
		icon.SetTarget(0, 0, float64(size), float64(size))
		icon.Draw(rasterx.NewDasher(size, size, rasterx.NewScannerGV(size, size, img, img.Bounds())), 1)
		f, err := os.Create(filepath.Join(os.Args[1], fmt.Sprintf("AppIcon%d.png", size)))
		if err != nil {
			panic(err)
		}
		if err = png.Encode(f, img); err != nil {
			panic(err)
		}
		if err = f.Close(); err != nil {
			panic(err)
		}
	}
}
