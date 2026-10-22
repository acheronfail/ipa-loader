//go:build linux || windows

package platform

import "ipa-loader/app/internal/runtimebundle"

func loaderRuntimeRoot() (string, error) { return runtimebundle.Root() }
