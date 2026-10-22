//go:build bundled

package runtimebundle

import _ "embed"

//go:embed payload.zip
var payload []byte
