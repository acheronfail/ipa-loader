package adimath

import (
	"encoding/binary"
	"fmt"
)

// BuildAndroidCPIMContext constructs the Android session cipher from the output
// of TransformAndroidSPIMBody. Singular byte banks cannot form a supported
// session context and are rejected before any block operation.
func BuildAndroidCPIMContext(material [240]byte) (AndroidCPIMContext, error) {
	var ctx AndroidCPIMContext
	var seed [64]byte
	copy(seed[:], material[176:])
	ctx.ByteBanks = BuildAndroidCPIMByteBanks(seed)
	for k := range ctx.ByteBanks {
		var seen [256]bool
		for _, v := range ctx.ByteBanks[k] {
			if seen[v] {
				return AndroidCPIMContext{}, fmt.Errorf("Android session byte bank %d is not bijective", k)
			}
			seen[v] = true
		}
	}
	ctx.WordBanks = buildAndroidCPIMWordBanks(&ctx.ByteBanks)
	for i := range ctx.Keys {
		ctx.Keys[i] = binary.LittleEndian.Uint32(material[4*i:])
	}
	return ctx, nil
}
