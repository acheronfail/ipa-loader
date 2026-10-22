//go:build linux || windows

package main

import (
	"context"
	"fmt"
	"ipa-loader/app/internal/runtimebundle"
	"os"
	"runtime"
	"time"
)

func runtimeCommand() bool {
	if runtimebundle.Embedded() {
		root, err := runtimebundle.Root()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		activateRuntime(root)
	}

	if len(os.Args) != 2 || os.Args[1] != "--check-runtime" {
		return false
	}
	root, err := runtimebundle.Root()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = validateRuntime(ctx, root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Embedded runtime verified (%s); private cache: %s\n", runtime.GOOS, root)
	return true
}
