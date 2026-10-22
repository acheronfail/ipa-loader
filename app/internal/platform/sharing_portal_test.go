package platform

import (
	"context"
	"reflect"
	"testing"

	"ipa-loader/app/internal/apple"
)

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
