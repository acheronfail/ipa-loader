package platform

import (
	"archive/zip"
	"context"
	"math"
	"os"
	"testing"
)

func TestLargeArchiveUsesAvailableDiskSpace(t *testing.T) {
	files := []*zip.File{{FileHeader: zip.FileHeader{Name: "Payload/Large.app/data.sqlite", UncompressedSize64: 5 << 30}}}
	if _, err := zipPlan(files); err != nil {
		t.Fatal("large app rejected despite representable size:", err)
	}
	if err := requireExtractionSpace(5<<30, 6<<30); err != nil {
		t.Fatal(err)
	}
	if err := requireExtractionSpace(5<<30, 4<<30); err == nil {
		t.Fatal("insufficient disk accepted")
	}
	files[0].UncompressedSize64 = math.MaxUint64
	if _, err := zipPlan(files); err == nil {
		t.Fatal("unrepresentable extraction size accepted")
	}
}

func TestPreflightOptionalLargeIPA(t *testing.T) {
	input := os.Getenv("IPA_LOADER_PREFLIGHT_IPA")
	if input == "" {
		t.Skip("optional read-only extraction and compatibility check")
	}
	if _, err := extractIPA(context.Background(), input, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
