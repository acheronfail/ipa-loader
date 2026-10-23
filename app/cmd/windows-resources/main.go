// windows-resources embeds the desktop brand in a Windows amd64 COFF resource.
// Run on the build host before compiling the Windows application.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"

	"github.com/akavel/rsrc/rsrc"
	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
	"golang.org/x/image/draw"
	"ipa-loader/app/internal/ui"
)

func run(output string) error {
	// Rasterize at intrinsic size so the SVG renderer preserves stroke widths.
	master := image.NewRGBA(image.Rect(0, 0, 128, 128))
	icon, err := oksvg.ReadIconStream(bytes.NewReader(ui.Brand.Content()))
	if err != nil {
		return err
	}
	icon.Draw(rasterx.NewDasher(128, 128, rasterx.NewScannerGV(128, 128, master, master.Bounds())), 1)
	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	var header, payload bytes.Buffer
	// ICONDIR followed by one ICONDIRENTRY per PNG image.
	for _, value := range []uint16{0, 1, uint16(len(sizes))} {
		_ = binary.Write(&header, binary.LittleEndian, value)
	}
	offset := uint32(6 + 16*len(sizes))
	for _, size := range sizes {
		img := image.NewRGBA(image.Rect(0, 0, size, size))
		draw.CatmullRom.Scale(img, img.Bounds(), master, master.Bounds(), draw.Src, nil)
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, img); err != nil {
			return err
		}
		// A zero width/height represents 256 pixels in an ICO directory.
		header.Write([]byte{byte(size), byte(size), 0, 0})
		_ = binary.Write(&header, binary.LittleEndian, uint16(1))
		_ = binary.Write(&header, binary.LittleEndian, uint16(32))
		_ = binary.Write(&header, binary.LittleEndian, uint32(encoded.Len()))
		_ = binary.Write(&header, binary.LittleEndian, offset)
		offset += uint32(encoded.Len())
		payload.Write(encoded.Bytes())
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	temp, err := os.MkdirTemp(filepath.Dir(output), ".windows-icon-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	ico := filepath.Join(temp, "ipa-loader.ico")
	if err := os.WriteFile(ico, append(header.Bytes(), payload.Bytes()...), 0644); err != nil {
		return err
	}
	return rsrc.Embed(output, "amd64", "", ico)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: windows-resources output_windows_amd64.syso")
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
