package platform

import (
	"ipa-loader/app/internal/apple"
	"strings"
	"sync"
)

var sharingPortalMu sync.Mutex

// No capability is disabled, no group is deleted, and no certificate state is
// touched here. A profile must still independently authorize every final value.
func (e *engine) provisionSharingGroups(client requestClient, session *apple.Session, team, appID string, groups []string, enabled bool) error {
	if len(groups) == 0 {
		return nil
	}
	if len(groups) > 64 || !validAccountComponent(team) || !validText(appID) {
		return failure("Invalid requested app groups")
	}
	seen := map[string]bool{}
	for _, group := range groups {
		if seen[group] || !strings.HasPrefix(group, "group.") || !bundlePattern.MatchString(group) || len(group) > 255 {
			return failure("Invalid requested app groups")
		}
		seen[group] = true
	}
	sharingPortalMu.Lock()
	defer sharingPortalMu.Unlock()
	if !enabled {
		e.emit("Enabling app-group capability")
		if _, err := e.request(client, session, "updateAppId", map[string]any{"appIdId": appID, "APG3427HIY": true}, team); err != nil {
			return err
		}
	}
	e.emit("Checking shared app groups")
	r, err := e.request(client, session, "listApplicationGroups", nil, team)
	if err != nil {
		return err
	}
	records, err := recordList(r, "applicationGroupList")
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		id, err := findApplicationGroup(records, group)
		if err != nil {
			return err
		}
		if id == "" {
			e.emit("Registering a shared app group")
			r, err = e.request(client, session, "addApplicationGroup", map[string]any{"identifier": group, "name": "IPA Loader shared storage"}, team)
			if err != nil {
				return err
			}
			record, ok := r["applicationGroup"].(map[string]any)
			if !ok || stringField(record, "identifier") != group || !validText(stringField(record, "applicationGroup")) {
				return failure("Developer service returned an invalid app group")
			}
			id = stringField(record, "applicationGroup")
		}
		ids = append(ids, id)
	}
	e.emit("Assigning app groups to this bundle")
	_, err = e.request(client, session, "assignApplicationGroupToAppId", map[string]any{"appIdId": appID, "applicationGroups": ids}, team)
	return err
}

func findApplicationGroup(records []map[string]any, identifier string) (string, error) {
	id := ""
	for _, record := range records {
		if stringField(record, "identifier") != identifier {
			continue
		}
		if id != "" || !validText(stringField(record, "applicationGroup")) {
			return "", failure("Developer service returned ambiguous app groups")
		}
		id = stringField(record, "applicationGroup")
	}
	return id, nil
}
