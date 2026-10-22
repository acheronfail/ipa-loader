package authclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClientConstructionDoesNotProvision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created", "state.json")
	t.Setenv("IPA_LOADER_ANISETTE_STATE_FILE", path)
	c := New()
	if c == nil || c.HTTPClient == nil {
		t.Fatal("missing portable client")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("construction touched machine storage", err)
	}
}
