package platform

import (
	"context"
	"ipa-loader/app/internal/apple"
	"reflect"
	"testing"
)

func TestNetworkRequestRequiresSupportedTypedArray(t *testing.T) {
	for _, value := range []any{true, "packet-tunnel-provider", []any{true}, []string{}, []string{"app-proxy-provider"}, []string{"packet-tunnel-provider", "dns-proxy"}} {
		if basicEntitlements(map[string]any{networkExtensionKey: value}) == nil {
			t.Fatalf("accepted unsupported value: %v", value)
		}
	}
	if err := basicEntitlements(map[string]any{networkExtensionKey: []string{"packet-tunnel-provider"}}); err != nil {
		t.Fatal(err)
	}
}
func TestNetworkAuthorizationUsesNewProfile(t *testing.T) {
	request := networkRequest{PacketTunnel: true}
	signing := map[string]any{}
	for _, profile := range []map[string]any{{}, {"Entitlements": map[string]any{networkExtensionKey: []string{"app-proxy-provider"}}}} {
		if authorizeNetwork(profile, signing, request) == nil {
			t.Fatal("unauthorized profile accepted")
		}
		if len(signing) != 0 {
			t.Fatal("unauthorized entitlement written")
		}
	}
	profile := map[string]any{"Entitlements": map[string]any{networkExtensionKey: []string{"packet-tunnel-provider", "app-proxy-provider"}}}
	if err := authorizeNetwork(profile, signing, request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(signing[networkExtensionKey], []string{"packet-tunnel-provider"}) {
		t.Fatal("copied excess authority")
	}
	empty := map[string]any{}
	if err := authorizeNetwork(profile, empty, networkRequest{}); err != nil || len(empty) != 0 {
		t.Fatal("invented unrequested capability")
	}
}
func TestNetworkPortalOnlyUpdatesRequestedCapability(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "enable", true: "reuse"}[enabled], func(t *testing.T) {
			var actions []string
			client := portalFunc(func(_ context.Context, _ *apple.Session, action string, params map[string]any, _ string) (map[string]any, error) {
				actions = append(actions, action)
				switch action {
				case "listAppIds":
					record := map[string]any{"identifier": "org.example.app.TEAM", "appIdId": "APP"}
					if enabled {
						record["enabledFeatures"] = []string{"NWEXT04537"}
						record["features"] = map[string]any{"NWEXT04537": true}
					}
					return map[string]any{"appIds": []any{record}}, nil
				case "updateAppId":
					if !reflect.DeepEqual(params, map[string]any{"appIdId": "APP", "NWEXT04537": true}) {
						t.Fatal("unexpected portal mutation", params)
					}
					return map[string]any{}, nil
				case "downloadTeamProvisioningProfile":
					return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": []byte("profile")}}, nil
				default:
					t.Fatal(action)
					return nil, nil
				}
			})
			e := newControllerTestEngine(context.Background(), t.TempDir())
			e.networkRequests = map[string]networkRequest{"org.example.app.TEAM": {PacketTunnel: true}}
			if _, err := e.provisionAppProfile(client, &apple.Session{}, "TEAM", "org.example.app.TEAM"); err != nil {
				t.Fatal(err)
			}
			expected := []string{"listAppIds", "downloadTeamProvisioningProfile"}
			if !enabled {
				expected = []string{"listAppIds", "updateAppId", "downloadTeamProvisioningProfile"}
			}
			if !reflect.DeepEqual(actions, expected) {
				t.Fatal(actions)
			}
		})
	}
}
