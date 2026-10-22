package accounts

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"ipa-loader/app/internal/apple"
)

type memoryVault struct {
	data                  []byte
	readError, writeError error
}

func (v *memoryVault) Read() ([]byte, error) { return append([]byte(nil), v.data...), v.readError }
func (v *memoryVault) Write(data []byte) error {
	if v.writeError != nil {
		return v.writeError
	}
	v.data = append([]byte(nil), data...)
	return nil
}
func session(username string) *apple.Session {
	return &apple.Session{Username: username, DSID: "synthetic-dsid", Token: "synthetic-token", IdentityFP: "synthetic-fingerprint"}
}

func TestSaveReloadSwitchRemove(t *testing.T) {
	vault := &memoryVault{}
	store := New(vault)
	for _, name := range []string{"first@example.invalid", "second@example.invalid"} {
		if err := store.Save(session(name)); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate a fresh process reading only the persisted credential data.
	store = New(vault)
	state, err := store.Load()
	if err != nil || len(state.Sessions) != 2 || state.Active != "second@example.invalid" || state.Sessions[0].Token != "synthetic-token" {
		t.Fatal("session persistence failed")
	}
	if err := store.Select("FIRST@example.invalid"); err != nil {
		t.Fatal(err)
	}
	updated := session("FIRST@example.invalid")
	updated.Token = "replacement-token"
	if err := store.Save(updated); err != nil {
		t.Fatal(err)
	}
	state, _ = store.Load()
	if len(state.Sessions) != 2 || state.Sessions[0].Token != "replacement-token" {
		t.Fatal("session renewal duplicated or lost account")
	}
	if err := store.Remove("first@example.invalid"); err != nil {
		t.Fatal(err)
	}
	state, _ = store.Load()
	if len(state.Sessions) != 1 || state.Active != "" || bytes.Contains(vault.data, []byte("replacement-token")) {
		t.Fatal("removed token retained")
	}
	if err := store.Remove("second@example.invalid"); err != nil {
		t.Fatal(err)
	}
	state, _ = New(vault).Load()
	if len(state.Sessions) != 0 || bytes.Contains(vault.data, []byte("synthetic-token")) {
		t.Fatal("last account retained")
	}
}

func TestInvalidOrFutureVaultIsNeverOverwritten(t *testing.T) {
	for _, data := range []string{`{`, `{"version":2}`, `{"version":1,"active":"missing"}`, `{"version":1,"sessions":[null]}`, strings.Repeat("x", maxData+1)} {
		vault := &memoryVault{data: []byte(data)}
		store := New(vault)
		if _, err := store.Load(); err == nil {
			t.Fatal("invalid vault accepted")
		}
		if err := store.Save(session("new@example.invalid")); err == nil {
			t.Fatal("invalid vault overwritten")
		}
		if string(vault.data) != data {
			t.Fatal("invalid vault changed")
		}
	}
}

func TestStorageFailuresAndRedaction(t *testing.T) {
	vault := &memoryVault{}
	store := New(vault)
	if err := store.Save(session("saved@example.invalid")); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), vault.data...)
	vault.writeError = errors.New("vault locked")
	if err := store.Remove("saved@example.invalid"); err == nil || !bytes.Equal(before, vault.data) {
		t.Fatal("failed removal changed storage")
	}
	vault.readError = errors.New("vault denied")
	if err := store.Save(session("new@example.invalid")); err == nil || !bytes.Equal(before, vault.data) {
		t.Fatal("read failure overwrote storage")
	}
	if err := store.Save(&apple.Session{Username: "incomplete"}); err == nil {
		t.Fatal("incomplete session saved")
	}
	text := fmt.Sprintf("%v %+v %#v", Snapshot{Sessions: []*apple.Session{session("private")}}, Snapshot{Sessions: []*apple.Session{session("private")}}, Snapshot{Sessions: []*apple.Session{session("private")}})
	if strings.Contains(text, "synthetic-token") || strings.Contains(text, "private\"") {
		t.Fatal("snapshot formatting exposed credentials")
	}
}

func TestConcurrentAccountSaves(t *testing.T) {
	store := New(&memoryVault{})
	var group sync.WaitGroup
	for i := 0; i < 10; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			if err := store.Save(session(fmt.Sprintf("user%d@example.invalid", i))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	state, err := store.Load()
	if err != nil || len(state.Sessions) != 10 {
		t.Fatal("concurrent save lost an account")
	}
}
