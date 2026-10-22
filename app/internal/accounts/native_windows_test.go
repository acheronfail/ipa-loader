//go:build windows

package accounts

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsVaultAccountsAndTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault", "sessions.dpapi")
	backend := nativeBackend{path: path}
	store := New(backend)
	state, err := store.Load()
	if err != nil || len(state.Sessions) != 0 {
		t.Fatal("isolated vault did not start empty", err)
	}
	for _, name := range []string{"first@example.invalid", "second@example.invalid"} {
		if err = store.Save(session(name)); err != nil {
			t.Fatal(err)
		}
	}
	store = New(backend)
	state, err = store.Load()
	if err != nil || len(state.Sessions) != 2 || state.Active != "second@example.invalid" || state.Sessions[0].Token != "synthetic-token" {
		t.Fatal("native vault did not round trip both accounts", err)
	}
	if err = store.Select("first@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove("second@example.invalid"); err != nil {
		t.Fatal(err)
	}
	state, err = New(backend).Load()
	if err != nil || len(state.Sessions) != 1 || state.Active != "first@example.invalid" {
		t.Fatal("native vault lost the selected account", err)
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-token", "first@example.invalid", "synthetic-dsid"} {
		if bytes.Contains(sealed, []byte(secret)) {
			t.Fatal("vault contains plaintext account data")
		}
	}
	sealed[len(sealed)-1] ^= 0xff
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(); err == nil {
		t.Fatal("tampered native vault accepted")
	}
	if err = store.Save(session("third@example.invalid")); err == nil {
		t.Fatal("tampered native vault overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, sealed) {
		t.Fatal("failed save changed tampered vault", err)
	}
}
