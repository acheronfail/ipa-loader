package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ipa-loader/app/internal/ipa"
)

type extensionSelectionKey struct{}

func WithExtensionSelection(ctx context.Context, selection *ipa.ExtensionSelection) context.Context {
	if selection == nil {
		return ctx
	}
	copy := &ipa.ExtensionSelection{Included: append([]string{}, selection.Included...)}
	return context.WithValue(ctx, extensionSelectionKey{}, copy)
}

func ExtensionSelection(ctx context.Context) *ipa.ExtensionSelection {
	selection, _ := ctx.Value(extensionSelectionKey{}).(*ipa.ExtensionSelection)
	if selection == nil {
		return nil
	}
	return &ipa.ExtensionSelection{Included: append([]string{}, selection.Included...)}
}

var extensionChoicesMu sync.Mutex

func extensionChoicePath(root, account, team, bundle string) string {
	key, _ := json.Marshal([]string{strings.ToLower(strings.TrimSpace(account)), team, bundle})
	sum := sha256.Sum256(key)
	return filepath.Join(root, "ipa-loader", "extension-choices", hex.EncodeToString(sum[:])+".json")
}

func LoadExtensionSelection(account, team, bundle string) (*ipa.ExtensionSelection, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return loadExtensionSelection(root, account, team, bundle)
}

func loadExtensionSelection(root, account, team, bundle string) (*ipa.ExtensionSelection, error) {
	extensionChoicesMu.Lock()
	defer extensionChoicesMu.Unlock()
	raw, err := readLimited(extensionChoicePath(root, account, team, bundle), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, failure("Saved extension choices could not be read")
	}
	var selection ipa.ExtensionSelection
	if json.Unmarshal(raw, &selection) != nil || len(selection.Included) > 64 {
		return nil, failure("Saved extension choices are invalid")
	}
	for _, id := range selection.Included {
		if !bundlePattern.MatchString(id) || len(id) > 255 {
			return nil, failure("Saved extension choices are invalid")
		}
	}
	return &selection, nil
}

func saveExtensionSelection(root, account, team, bundle string, selection *ipa.ExtensionSelection) error {
	if selection == nil {
		return nil
	}
	extensionChoicesMu.Lock()
	defer extensionChoicesMu.Unlock()
	path := extensionChoicePath(root, account, team, bundle)
	if err := privateDir(filepath.Dir(path)); err != nil {
		return err
	}
	raw, err := json.Marshal(selection)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".choices-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	return os.Rename(file.Name(), path)
}
