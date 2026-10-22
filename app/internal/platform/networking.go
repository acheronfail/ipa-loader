package platform

const networkExtensionKey = "com.apple.developer.networking.networkextension"

type networkRequest struct{ PacketTunnel bool }

// Only the explicitly supported provider type is requested. The new profile,
// rather than the input signature or a successful portal update, grants access.
func requestedNetwork(ent map[string]any) (networkRequest, error) {
	var r networkRequest
	value, present := ent[networkExtensionKey]
	if !present {
		return r, nil
	}
	values, err := sharingStrings(value)
	if err != nil || len(values) != 1 || values[0] != "packet-tunnel-provider" {
		return r, failure("Only the packet-tunnel-provider Network Extension capability is supported")
	}
	r.PacketTunnel = true
	return r, nil
}
func readNetworkRequest(path string) (networkRequest, error) {
	b, err := readLimited(path, 512<<20)
	if err != nil {
		return networkRequest{}, err
	}
	slices, err := machSlices(b)
	if err != nil {
		return networkRequest{}, err
	}
	ent, err := consistentSliceEntitlements(slices)
	if err != nil {
		return networkRequest{}, err
	}
	return requestedNetwork(ent)
}
func authorizeNetwork(profile, signing map[string]any, request networkRequest) error {
	if !request.PacketTunnel {
		return nil
	}
	ent := mapField(profile, "Entitlements")
	if !contains(textList(ent[networkExtensionKey]), "packet-tunnel-provider") {
		return failure("The provisioning profile does not authorize the packet tunnel. Select a paid developer team with Network Extensions enabled")
	}
	signing[networkExtensionKey] = []string{"packet-tunnel-provider"}
	return nil
}
