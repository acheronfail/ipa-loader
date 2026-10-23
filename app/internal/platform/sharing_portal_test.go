package platform

import (
	"context"
	"errors"
	"howett.net/plist"
	"reflect"
	"testing"

	"ipa-loader/app/internal/apple"
)

func TestAppGroupProvisioningChecksAuthenticatedAccountType(t *testing.T) {
	for _, kind := range []string{"free", "paid", "foreign team", "malformed flag", "invalid CMS"} {
		t.Run(kind, func(t *testing.T) {
			p := map[string]any{"TeamIdentifier": []any{"TEAM"}, "LocalProvision": kind == "free"}
			if kind == "foreign team" {
				p["TeamIdentifier"] = []any{"OTHER"}
			}
			if kind == "malformed flag" {
				p["LocalProvision"] = "true"
			}
			raw, _ := plist.Marshal(p, plist.XMLFormat)
			e := newControllerTestEngine(context.Background(), t.TempDir())
			e.decodeProfile = func(string) ([]byte, error) {
				if kind == "invalid CMS" {
					return nil, errors.New("bad CMS")
				}
				return raw, nil
			}
			var actions []string
			client := portalFunc(func(_ context.Context, _ *apple.Session, action string, _ map[string]any, _ string) (map[string]any, error) {
				actions = append(actions, action)
				switch action {
				case "listAppIds":
					return map[string]any{"appIds": []any{map[string]any{"identifier": "org.example.app.TEAM", "appIdId": "APP", "enabledFeatures": []any{"APG3427HIY"}, "features": map[string]any{"APG3427HIY": true}}}}, nil
				case "downloadTeamProvisioningProfile":
					return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": []byte("CMS")}}, nil
				case "listApplicationGroups":
					if kind != "paid" {
						t.Fatal("non-paid or invalid profile attempted app-group provisioning")
					}
					return map[string]any{"applicationGroupList": []any{map[string]any{"identifier": "group.org.example.TEAM", "applicationGroup": "GROUP"}}}, nil
				case "assignApplicationGroupToAppId":
					return map[string]any{}, nil
				default:
					t.Fatalf("unexpected action %s", action)
					return nil, nil
				}
			})
			_, err := e.provisionAppProfile(client, &apple.Session{}, "TEAM", "org.example.app.TEAM", "group.org.example.TEAM")
			valid := kind == "free" || kind == "paid"
			if (err == nil) != valid {
				t.Fatalf("account profile policy: %v", err)
			}
			if kind == "paid" {
				if len(actions) != 5 {
					t.Fatalf("paid provisioning incomplete: %v", actions)
				}
			} else if len(actions) != 2 {
				t.Fatalf("unexpected account provisioning operations: %v", actions)
			}
		})
	}
}

func TestSharingPortalReuseAndAssignment(t *testing.T) {
	var actions []string
	client := portalFunc(func(ctx context.Context, s *apple.Session, action string, params map[string]any, team string) (map[string]any, error) {
		actions = append(actions, action)
		switch action {
		case "updateAppId":
			if params["APG3427HIY"] != true {
				t.Fatal("group feature not enabled")
			}
			return map[string]any{}, nil
		case "listApplicationGroups":
			return map[string]any{"applicationGroupList": []any{map[string]any{"identifier": "group.org.example.existing.TEAM", "applicationGroup": "EXISTING"}}}, nil
		case "addApplicationGroup":
			if params["identifier"] != "group.org.example.new.TEAM" {
				t.Fatal("existing group recreated")
			}
			return map[string]any{"applicationGroup": map[string]any{"identifier": params["identifier"], "applicationGroup": "NEW"}}, nil
		case "assignApplicationGroupToAppId":
			if params["appIdId"] != "APP" || !reflect.DeepEqual(params["applicationGroups"], []string{"EXISTING", "NEW"}) {
				t.Fatal("incorrect group assignment")
			}
			return map[string]any{}, nil
		default:
			t.Fatal("unexpected portal operation:", action)
			return nil, nil
		}
	})
	e := newControllerTestEngine(context.Background(), t.TempDir())
	if err := e.provisionSharingGroups(client, &apple.Session{}, "TEAM", "APP", []string{"group.org.example.existing.TEAM", "group.org.example.new.TEAM"}, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actions, []string{"updateAppId", "listApplicationGroups", "addApplicationGroup", "assignApplicationGroupToAppId"}) {
		t.Fatal("unexpected portal sequence", actions)
	}
}

func TestSharingPortalRejectsAmbiguousGroups(t *testing.T) {
	if _, err := findApplicationGroup([]map[string]any{{"identifier": "group.a.b", "applicationGroup": "ONE"}, {"identifier": "group.a.b", "applicationGroup": "TWO"}}, "group.a.b"); err == nil {
		t.Fatal("duplicate group assignment accepted")
	}
	e := newControllerTestEngine(context.Background(), t.TempDir())
	if err := e.provisionSharingGroups(nil, nil, "TEAM", "APP", nil, false); err != nil {
		t.Fatal("empty groups should make no portal calls")
	}
}
