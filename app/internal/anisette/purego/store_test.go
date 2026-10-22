package purego

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func syntheticStoreState() *State {
	s := &State{Version: 1, DeviceID: "synthetic-device", LocalUser: strings.Repeat("A", 64), Routing: "17106176"}
	s.Machine.Environment = -2
	return s
}
func TestStoreProvisionOnceAndReloadIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "machine.json")
	store := NewStore(path, nil)
	calls := 0
	store.provision = func(context.Context, *http.Client) (*State, error) { calls++; return syntheticStoreState(), nil }
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Headers(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("provisioned %d times", calls)
	}
	reloaded := NewStore(path, nil)
	reloaded.provision = func(context.Context, *http.Client) (*State, error) {
		t.Fatal("reprovisioned saved identity")
		return nil, nil
	}
	h, err := reloaded.Headers(context.Background())
	if err != nil || h["X-Mme-Device-Id"] != "synthetic-device" {
		t.Fatal("identity reload failed", err)
	}
}
func TestStorePreservesCorruptionAndHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "machine.json")
	if err := ensureStateDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := writeState(path, []byte("broken-state")); err != nil {
		t.Fatal(err)
	}
	store := NewStore(path, nil)
	store.provision = func(context.Context, *http.Client) (*State, error) {
		t.Fatal("silently replaced corrupt identity")
		return nil, nil
	}
	if _, err := store.Headers(context.Background()); err == nil {
		t.Fatal("accepted invalid saved state")
	}
	raw, err := readState(path)
	if err != nil || string(raw) != "broken-state" {
		t.Fatal("corrupt state was changed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Headers(ctx); err != context.Canceled {
		t.Fatal("ignored cancellation", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
