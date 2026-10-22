package main

import (
	"context"
	"ipa-loader/app/internal/platform"
	"os"
	"path/filepath"
)

func validateRuntime(ctx context.Context, root string) error {
	return platform.ValidateLinuxRuntime(ctx, root)
}

func activateRuntime(root string) {
	os.Setenv("PATH", filepath.Join(root, "keyring-linux")+string(os.PathListSeparator)+os.Getenv("PATH"))
}
