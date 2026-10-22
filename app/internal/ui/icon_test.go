package ui

import (
	"bytes"
	"image/png"
	"testing"
)

func TestDockIconPreservesTransparentMask(t *testing.T) {
	resource := macDockIcon()
	img, err := png.Decode(bytes.NewReader(resource.Content()))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 1024 || img.Bounds().Dy() != 1024 {
		t.Fatal("Dock icon lost its intrinsic canvas size")
	}
	for _, point := range [][2]int{{0, 0}, {512, 99}, {99, 512}, {924, 512}, {512, 924}, {110, 110}} {
		_, _, _, alpha := img.At(point[0], point[1]).RGBA()
		if alpha != 0 {
			t.Errorf("Dock margin/corner is opaque at %v", point)
		}
	}
	for _, point := range [][2]int{{512, 101}, {101, 512}, {512, 512}, {150, 200}} {
		_, _, _, alpha := img.At(point[0], point[1]).RGBA()
		if alpha != 0xffff {
			t.Errorf("Dock tile is not opaque at %v", point)
		}
	}
}
