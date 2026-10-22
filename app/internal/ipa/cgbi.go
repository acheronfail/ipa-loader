package ipa

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"image"
	"image/png"
	"io"
)

// iOS optimized PNGs use raw deflate and premultiplied BGRA pixels.
func decodeCgBI(data []byte) ([]byte, error) {
	bad := errors.New("Unsupported optimized app icon")
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return nil, bad
	}
	w, h := 0, 0
	var compressed []byte
	for off := 8; off+12 <= len(data); {
		n := int(binary.BigEndian.Uint32(data[off:]))
		if n > len(data)-off-12 {
			return nil, bad
		}
		kind := string(data[off+4 : off+8])
		b := data[off+8 : off+8+n]
		switch kind {
		case "IHDR":
			if n != 13 || b[8] != 8 || b[9] != 6 || b[10] != 0 || b[11] != 0 || b[12] != 0 {
				return nil, bad
			}
			w = int(binary.BigEndian.Uint32(b))
			h = int(binary.BigEndian.Uint32(b[4:]))
		case "IDAT":
			compressed = append(compressed, b...)
		}
		off += n + 12
	}
	if w <= 0 || h <= 0 || w > 2048 || h > 2048 || len(compressed) > 10<<20 {
		return nil, bad
	}
	stride := w * 4
	expected := (stride + 1) * h
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, int64(expected+1)))
	if err != nil || len(raw) != expected {
		return nil, bad
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	previous := make([]byte, stride)
	for y := 0; y < h; y++ {
		row := raw[y*(stride+1)+1 : (y+1)*(stride+1)]
		filter := raw[y*(stride+1)]
		if filter > 4 {
			return nil, bad
		}
		for x := range row {
			var a, b, c byte
			if x >= 4 {
				a = row[x-4]
				c = previous[x-4]
			}
			b = previous[x]
			switch filter {
			case 1:
				row[x] += a
			case 2:
				row[x] += b
			case 3:
				row[x] += byte((int(a) + int(b)) / 2)
			case 4:
				row[x] += paeth(a, b, c)
			}
		}
		for x := 0; x < stride; x += 4 {
			alpha := int(row[x+3])
			dst := y*img.Stride + x
			for channel := 0; channel < 3; channel++ {
				v := int(row[x+2-channel])
				if alpha > 0 {
					v = min(255, (v*255+alpha/2)/alpha)
				} else {
					v = 0
				}
				img.Pix[dst+channel] = byte(v)
			}
			img.Pix[dst+3] = byte(alpha)
		}
		copy(previous, row)
	}
	var out bytes.Buffer
	err = png.Encode(&out, img)
	return out.Bytes(), err
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
