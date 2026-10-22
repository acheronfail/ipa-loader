//go:build darwin && cgo

package accounts

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestIsolatedNativeKeychain(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_KEYCHAIN") != "1" {
		t.Skip("explicit isolated macOS Keychain integration check")
	}
	backend := nativeBackend{service: fmt.Sprintf("org.example.ipaloader.test.%d.%d", os.Getpid(), time.Now().UnixNano())}
	t.Cleanup(func() {
		if err := backend.deleteVault(); err != nil {
			t.Error(err)
		}
	})
	store := New(backend)
	state, err := store.Load()
	if err != nil || len(state.Sessions) != 0 {
		t.Fatal("isolated Keychain entry was not empty")
	}
	if err = store.Save(session("synthetic@example.invalid")); err != nil {
		t.Fatal(err)
	}
	state, err = New(backend).Load()
	if err != nil || len(state.Sessions) != 1 || state.Sessions[0].Token != "synthetic-token" {
		t.Fatal("Keychain session did not round trip")
	}
	if err = store.Save(session("second@example.invalid")); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove("synthetic@example.invalid"); err != nil {
		t.Fatal(err)
	}
	state, err = New(backend).Load()
	if err != nil || len(state.Sessions) != 1 || state.Sessions[0].Username != "second@example.invalid" {
		t.Fatal("Keychain update lost the other account")
	}
	if err = backend.deleteVault(); err != nil {
		t.Fatal(err)
	}
	state, err = New(backend).Load()
	if err != nil || len(state.Sessions) != 0 {
		t.Fatal("isolated Keychain entry was not deleted")
	}
}
