// Package authclient constructs the application's shared portable Apple client.
package authclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"ipa-loader/app/internal/anisette/purego"
	"ipa-loader/app/internal/apple"
)

// Public protocol metadata from the successful live compatibility check. These
// are not the host's serial number, ADI state or account identity. Keep stable
// across restarts so saved sessions use the same request description.
const ClientDescription = "<Mac16,12> <macOS;15.6;24G84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

// New uses persistent pure-Go state. The explicit path override lets acceptance
// runs use a disposable identity without changing the desktop's saved identity.
// No filesystem or network operation is performed until headers are needed.
func New() *apple.Client {
	path := os.Getenv("IPA_LOADER_ANISETTE_STATE_FILE")
	var pathErr error
	if path == "" {
		var root string
		root, pathErr = os.UserConfigDir()
		path = filepath.Join(root, "ipa-loader", "anisette", "machine-state.json")
	}
	store := purego.NewStore(path, apple.New(nil).HTTPClient)
	provider := store.Headers
	if pathErr != nil {
		provider = func(context.Context) (map[string]string, error) {
			return nil, errors.New("Could not locate private machine storage")
		}
	}
	client, err := apple.NewPortableAuthKit(provider, ClientDescription)
	if err != nil {
		panic("invalid built-in Apple client description")
	}
	return client
}
