package platform

import (
	"context"
	"strings"
	"time"
)

// IOSApp is the small, non-secret snapshot displayed by the native app list.
type IOSApp struct {
	BundleID   string
	Name       string
	Version    string
	Build      string
	Team       string
	Account    string
	Icon       []byte `json:"Icon,omitempty"`
	Expires    time.Time
	Refreshed  time.Time
	Self       bool
	CanRefresh bool
}
type iosAppRecord struct {
	IOSApp
	Package        string
	ProfileExpires time.Time
	Binding        *refreshBinding
	ProfileRefresh *profileRefreshReceipt
	// CheckedAccount is verified by the portal against Binding's original signer.
	// It is not an installation record or evidence that profiles were renewed.
	CheckedAccount string
}

// Replacing the signed app invalidates receipts for its previous code/profile set.
func (record *iosAppRecord) setRefreshBinding(binding *refreshBinding) {
	if !sameRefreshCode(binding, record.Binding) {
		record.ProfileRefresh = nil
	}
	record.Binding = binding
}

// Match the full signed application identifier, including its prefix. Multiple
// installed profiles may authorize the same app: only show an exact date when
// all matching profiles agree. Never substitute profile creation for a refresh.
func inventoryAppExpiry(item map[string]any, profiles []map[string]any) time.Time {
	identifier := stringField(mapField(item, "Entitlements"), "application-identifier")
	if identifier == "" {
		identifier = stringField(item, "ApplicationIdentifier")
	}
	if identifier == "" {
		return time.Time{}
	}
	var expiry time.Time
	for _, profile := range profiles {
		authorized := stringField(mapField(profile, "Entitlements"), "application-identifier")
		match := authorized == identifier
		if strings.HasSuffix(authorized, ".*") {
			match = strings.HasPrefix(identifier, strings.TrimSuffix(authorized, "*"))
		}
		if !match {
			continue
		}
		date, ok := profile["ExpirationDate"].(time.Time)
		if !ok || date.IsZero() {
			return time.Time{}
		}
		if !expiry.IsZero() && !date.Equal(expiry) {
			return time.Time{}
		}
		expiry = date
	}
	return expiry
}

func reconcileIOSApps(records map[string]iosAppRecord, inventory []map[string]any, profiles []map[string]any) map[string]IOSApp {
	apps := map[string]IOSApp{}
	for _, item := range inventory {
		id := stringField(item, "CFBundleIdentifier")
		if !bundlePattern.MatchString(id) {
			continue
		}
		record, tracked := records[id]
		ent := mapField(item, "Entitlements")
		expiry := inventoryAppExpiry(item, profiles)
		// App Store apps have neither a development entitlement nor a matching
		// installed provisioning profile. Do not fill My Apps with App Store apps.
		if !tracked && ent["get-task-allow"] != true && expiry.IsZero() {
			continue
		}
		app := record.IOSApp
		app.BundleID = id
		app.Name = stringField(item, "CFBundleDisplayName")
		if app.Name == "" {
			app.Name = id
		}
		app.Version = stringField(item, "CFBundleShortVersionString")
		app.Build = stringField(item, "CFBundleVersion")
		team := stringField(ent, "com.apple.developer.team-identifier")
		changed := tracked && (app.Version != record.Version || app.Build != record.Build || (team != "" && record.Team != "" && team != record.Team))
		if changed {
			app.Expires = time.Time{}
			app.Account = ""
			app.Refreshed = time.Time{}
		}
		if profiles != nil {
			// Inventory identifies the containing app's profile. A recorded extension
			// may expire sooner, so compare the parent profile separately and preserve
			// the earlier effective deadline when the signed installation still matches.
			previous := record.ProfileExpires
			if previous.IsZero() {
				previous = record.Expires
			}
			if !previous.IsZero() && !previous.Equal(expiry) {
				app.Refreshed = time.Time{}
				app.Account = ""
				app.Expires = expiry
			} else if changed || previous.IsZero() {
				app.Expires = expiry
			}
		}
		if !changed && matchingRefreshApp(record.Binding, []map[string]any{item}) {
			if refreshReceiptPresent(record.ProfileRefresh, profiles) {
				app.Expires = record.ProfileRefresh.Expires
				app.Refreshed = record.ProfileRefresh.Refreshed
				app.Account = record.ProfileRefresh.Account
			} else if boundExpiry := installedBindingExpiry(record.Binding, profiles); !boundExpiry.IsZero() {
				app.Expires = boundExpiry
				if record.ProfileRefresh == nil {
					app.Refreshed = record.Refreshed
					app.Account = record.Account
				}
				if app.Account == "" {
					app.Account = record.CheckedAccount
				}
			}
		}
		if team != "" {
			app.Team = team
		}
		apps[id] = app
	}
	return apps
}

type iosPackageRetentionKey struct{}

// WithIOSPackageRetention carries the per-install choice from native review.
func WithIOSPackageRetention(ctx context.Context, retain bool) context.Context {
	return context.WithValue(ctx, iosPackageRetentionKey{}, retain)
}
func IOSPackageRetention(ctx context.Context) bool {
	v, ok := ctx.Value(iosPackageRetentionKey{}).(bool)
	return !ok || v
}
