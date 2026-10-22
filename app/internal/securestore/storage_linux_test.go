//go:build linux

package securestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretServiceRoundTripWithoutPlaintextFallback(t *testing.T) {
	original := secretCommand
	t.Cleanup(func() { secretCommand = original })
	records := map[string][]byte{}
	secretCommand = func(_ context.Context, input []byte, args ...string) ([]byte, []byte, error) {
		key := args[len(args)-1]
		if args[0] == "store" {
			records[key] = bytes.Clone(input)
			return nil, nil, nil
		}
		return bytes.Clone(records[key]), nil, nil
	}
	path := filepath.Join(t.TempDir(), "credentials.secret")
	data := []byte("synthetic-secret")
	if err := Write(path, data); err != nil {
		t.Fatal(err)
	}
	result, err := Read(path, 1024)
	if err != nil || !bytes.Equal(result, data) {
		t.Fatal("secret roundtrip failed", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret persisted as a file")
	}
	secretCommand = func(context.Context, []byte, ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("keyring unavailable")
	}
	if err := Write(path, data); err == nil {
		t.Fatal("unavailable vault accepted write")
	}
	if _, err := Read(path, 1024); err == nil {
		t.Fatal("unavailable vault reported absence")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed vault fell back to plaintext")
	}
}
func TestSecretServiceRejectsOversizedAndMalformedRecords(t *testing.T) {
	original := secretCommand
	t.Cleanup(func() { secretCommand = original })
	path := filepath.Join(t.TempDir(), "record")
	for _, record := range []string{"!bad-base64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 65)))} {
		secretCommand = func(context.Context, []byte, ...string) ([]byte, []byte, error) { return []byte(record), nil, nil }
		if _, err := Read(path, 64); err == nil {
			t.Fatal("invalid record accepted")
		}
	}
}
func TestLinuxPrivateFilesRejectLinksAndPublicPermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	f, err := CreatePrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = CheckFile(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if CheckFile(path) == nil {
		t.Fatal("public file accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err = os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if CheckFile(path) == nil {
		t.Fatal("hard link accepted")
	}
	os.Remove(link)
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if CheckFile(link) == nil {
		t.Fatal("symlink accepted")
	}
}
