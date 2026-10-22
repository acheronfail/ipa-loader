package platform

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"
)

func sharingMachO() []byte {
	b := make([]byte, 1024)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x100000c)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], 152)
	binary.LittleEndian.PutUint32(b[32:], 0x19)
	binary.LittleEndian.PutUint32(b[36:], 152)
	binary.LittleEndian.PutUint32(b[96:], 1)
	binary.LittleEndian.PutUint32(b[152:], 512)
	copy(b[512:], "owned fixture instructions and data")
	return b
}

func TestSharingLoadCommandPreservesSectionsAndIsIdempotent(t *testing.T) {
	input := sharingMachO()
	original := append([]byte(nil), input...)
	output, err := addSharingLoadCommand(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, input) || !bytes.Equal(input[512:], output[512:]) || len(output) != len(input) {
		t.Fatal("injection mutated source or shifted code/data")
	}
	if binary.LittleEndian.Uint32(output[16:]) != 2 || !bytes.Contains(output, []byte(sharingLibraryLoadPath)) {
		t.Fatal("load command missing")
	}
	again, err := addSharingLoadCommand(output)
	if err != nil || !bytes.Equal(output, again) {
		t.Fatal("re-signing duplicated the runtime load command")
	}
}

func TestSharingLoadCommandRejectsUnsafeHeader(t *testing.T) {
	for _, kind := range []string{"no room", "occupied", "bad section table", "truncated", "arm64e", "fat"} {
		t.Run(kind, func(t *testing.T) {
			b := sharingMachO()
			switch kind {
			case "no room":
				binary.LittleEndian.PutUint32(b[152:], 192)
			case "occupied":
				b[184] = 1
			case "bad section table":
				binary.LittleEndian.PutUint32(b[96:], 100)
			case "truncated":
				b = b[:40]
			case "arm64e":
				binary.LittleEndian.PutUint32(b[8:], 2)
			case "fat":
				binary.LittleEndian.PutUint32(b, 0xbebafeca)
			}
			if _, err := addSharingLoadCommand(b); err == nil {
				t.Fatal("unsafe adapter injection accepted")
			}
		})
	}
}

func TestNativeSharingAdapterBuild(t *testing.T) {
	if os.Getenv("IPA_LOADER_NATIVE_SHARING_BUILD") != "1" {
		t.Skip("optional iPhoneOS SDK adapter build")
	}
	if _, err := newControllerTestEngine(context.Background(), t.TempDir()).buildSharingLibrary(); err != nil {
		t.Fatal(err)
	}
}
