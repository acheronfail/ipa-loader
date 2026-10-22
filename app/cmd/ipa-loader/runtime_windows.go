package main

import (
	"context"
	"ipa-loader/app/internal/platform"
)

func validateRuntime(ctx context.Context, root string) error {
	return platform.ValidateWindowsRuntime(ctx, root)
}

func activateRuntime(root string) {}
