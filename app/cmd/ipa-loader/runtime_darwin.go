package main

import (
	"context"
	"fmt"
	"ipa-loader/app/internal/platform"
	"os"
	"path/filepath"
	"time"
)

func runtimeCommand() bool {
	if len(os.Args) != 2 || os.Args[1] != "--check-runtime" {
		return false
	}
	executable, err := os.Executable()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = platform.ValidateDarwinRuntime(ctx, filepath.Join(filepath.Dir(filepath.Dir(executable)), "Resources"))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("macOS runtime verified; bundled sharing adapter, Go signing and system usbmuxd; no Xcode runtime requirement")
	return true
}
