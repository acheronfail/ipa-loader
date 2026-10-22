package ipa

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func archive(t *testing.T, files map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "app.ipa")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for name, b := range files {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	f.Close()
	return p
}
func infoBytes(t *testing.T, format int) []byte {
	t.Helper()
	b, e := plist.Marshal(map[string]any{"CFBundleIdentifier": "org.example.fixture", "CFBundleDisplayName": "Sample App", "CFBundleShortVersionString": "2.0", "CFBundleVersion": "4", "CFBundleIcons": map[string]any{"CFBundlePrimaryIcon": map[string]any{"CFBundleIconFiles": []string{"AppIcon"}}}}, format)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestMetadataAndLargestIcon(t *testing.T) {
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		makeIcon := func(size int) []byte {
			var out bytes.Buffer
			im := image.NewNRGBA(image.Rect(0, 0, size, size))
			im.Set(0, 0, color.NRGBA{10, 20, 30, 255})
			png.Encode(&out, im)
			return out.Bytes()
		}
		file := archive(t, map[string][]byte{"Payload/Test.app/Info.plist": infoBytes(t, format), "Payload/Test.app/AppIcon60.png": makeIcon(60), "Payload/Test.app/AppIcon180.png": makeIcon(180)})
		i, e := Inspect(file)
		if e != nil {
			t.Fatal(e)
		}
		if i.Name != "Sample App" || i.BundleID != "org.example.fixture" || i.Version != "2.0" || i.Build != "4" {
			t.Fatalf("bad metadata: %+v", i)
		}
		config, _, e := image.DecodeConfig(bytes.NewReader(i.Icon))
		if e != nil || config.Width != 180 {
			t.Fatal("largest declared icon not selected", e)
		}
	}
}
func TestUnsafeIPAAndMultipleApps(t *testing.T) {
	for _, extra := range []string{"../escape", "Payload/../escape", "/absolute", "Payload/Test.app/./Bad", "Payload/Test.app/bad\\path", "Payload/Other.app/Info.plist"} {
		t.Run(extra, func(t *testing.T) {
			p := archive(t, map[string][]byte{"Payload/Test.app/Info.plist": infoBytes(t, plist.XMLFormat), extra: []byte("bad")})
			if _, e := Inspect(p); e == nil {
				t.Fatal("unsafe/multiple apps accepted")
			}
		})
	}
}
func TestMissingIconStillSelectsApp(t *testing.T) {
	p := archive(t, map[string][]byte{"Payload/Test.app/Info.plist": infoBytes(t, plist.XMLFormat)})
	i, e := Inspect(p)
	if e != nil || i == nil || len(i.Icon) != 0 {
		t.Fatal("missing icon should use UI placeholder", e)
	}
}

func TestPreviewDoesNotReadLargeResources(t *testing.T) {
	p := filepath.Join(t.TempDir(), "large.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, err := z.Create("Payload/Test.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(infoBytes(t, plist.XMLFormat)); err != nil {
		t.Fatal(err)
	}
	// Only the directory record is needed for a resource that preview must
	// never decompress. No multi-gigabyte allocation or extraction is performed.
	if _, err = z.CreateRaw(&zip.FileHeader{Name: "Payload/Test.app/data.sqlite", Method: zip.Deflate, UncompressedSize64: 5 << 30}); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(p); err != nil {
		t.Fatal("large unrelated resource prevented metadata preview:", err)
	}
}

func TestInspectOptionalUserIPA(t *testing.T) {
	path := os.Getenv("IPA_LOADER_INSPECT_IPA")
	if path == "" {
		t.Skip("optional read-only IPA metadata check")
	}
	if _, err := Inspect(path); err != nil {
		t.Fatal(err)
	}
}

func TestUnicodeNamesAndNormalizationCollision(t *testing.T) {
	files := map[string][]byte{"Payload/Test.app/Info.plist": infoBytes(t, plist.XMLFormat),
		"Payload/Test.app/Café.txt": []byte("resource")}
	if _, err := Inspect(archive(t, files)); err != nil {
		t.Fatal("valid Unicode resource rejected", err)
	}
	files["Payload/Test.app/Cafe\u0301.txt"] = []byte("alias")
	if _, err := Inspect(archive(t, files)); err == nil {
		t.Fatal("normalization collision accepted")
	}
}
func TestCgBIColorAndAlpha(t *testing.T) {
	var compressed bytes.Buffer
	w, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	w.Write([]byte{0, 25, 50, 100, 128})
	w.Close()
	data := []byte{137, 80, 78, 71, 13, 10, 26, 10}
	chunk := func(name string, payload []byte) {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(payload)))
		data = append(data, b...)
		data = append(data, name...)
		data = append(data, payload...)
		data = append(data, 0, 0, 0, 0)
	}
	chunk("CgBI", nil)
	header := make([]byte, 13)
	binary.BigEndian.PutUint32(header, 1)
	binary.BigEndian.PutUint32(header[4:], 1)
	header[8] = 8
	header[9] = 6
	chunk("IHDR", header)
	chunk("IDAT", compressed.Bytes())
	chunk("IEND", nil)
	result, e := normalizePNG(data)
	if e != nil {
		t.Fatal(e)
	}
	im, e := png.Decode(bytes.NewReader(result))
	if e != nil {
		t.Fatal(e)
	}
	pixel := color.NRGBAModel.Convert(im.At(0, 0)).(color.NRGBA)
	if pixel.R != 199 || pixel.G != 100 || pixel.B != 50 || pixel.A != 128 {
		t.Fatalf("wrong unpremultiplied BGRA color %+v", pixel)
	}
	for _, bad := range [][]byte{data[:20], append([]byte{}, data[:8]...)} {
		if _, e := decodeCgBI(bad); e == nil {
			t.Fatal("truncated icon accepted")
		}
	}
}
