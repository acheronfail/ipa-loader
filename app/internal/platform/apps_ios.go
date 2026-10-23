//go:build ios

package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"ipa-loader/app/internal/iosnative"
	ipainfo "ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/mobiledevice"
)

var appsMu sync.Mutex
var appsGeneration uint64

func appsDirectory() string {
	root, _ := os.UserConfigDir()
	return filepath.Join(root, "ipa-loader", "apps")
}
func appRecordPath(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(appsDirectory(), hex.EncodeToString(sum[:])+".json")
}
func readAppRecords() map[string]iosAppRecord {
	records := map[string]iosAppRecord{}
	entries, _ := os.ReadDir(appsDirectory())
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := readLimited(filepath.Join(appsDirectory(), entry.Name()), 1<<20)
		var record iosAppRecord
		if err == nil && json.Unmarshal(raw, &record) == nil && bundlePattern.MatchString(record.BundleID) {
			records[record.BundleID] = record
		}
	}
	return records
}
func saveAppRecord(record iosAppRecord) error {
	if err := privateDir(appsDirectory()); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := appRecordPath(record.BundleID)
	if err = os.WriteFile(path+".tmp", raw, 0600); err != nil {
		return err
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		return err
	}
	appsGeneration++
	return nil
}
func appProfileDates(path string) (time.Time, error) {
	paths := []string{filepath.Join(path, "embedded.mobileprovision")}
	extensions, err := directExtensionPaths(path)
	if err != nil {
		return time.Time{}, err
	}
	for _, extension := range extensions {
		paths = append(paths, filepath.Join(extension, "embedded.mobileprovision"))
	}
	var expiry time.Time
	for _, profilePath := range paths {
		raw, err := decodeProfile(profilePath)
		if err != nil {
			return time.Time{}, err
		}
		profile, err := dictionary(raw)
		if err != nil {
			return time.Time{}, err
		}
		date, ok := profile["ExpirationDate"].(time.Time)
		if !ok || date.IsZero() {
			return time.Time{}, errors.New("Profile expiry is missing")
		}
		if expiry.IsZero() || date.Before(expiry) {
			expiry = date
		}
	}
	return expiry, nil
}
func recordIOSInstall(app appInfo, account string, binding *refreshBinding) error {
	expiry, err := appProfileDates(app.Path)
	if err != nil {
		return err
	}
	raw, _ := os.ReadFile(filepath.Join(app.Path, "Info.plist"))
	info, _ := dictionary(raw)
	name := stringField(info, "CFBundleDisplayName")
	if name == "" {
		name = stringField(info, "CFBundleName")
	}
	if name == "" {
		name = app.BundleID
	}
	appsMu.Lock()
	defer appsMu.Unlock()
	old := readAppRecords()[app.BundleID]
	profileRaw, _ := decodeProfile(filepath.Join(app.Path, "embedded.mobileprovision"))
	profile, _ := dictionary(profileRaw)
	teams := textList(profile["TeamIdentifier"])
	team := ""
	if len(teams) == 1 {
		team = teams[0]
	}
	old.Binding, old.ProfileRefresh = binding, nil
	old.CheckedAccount = ""
	old.ProfileExpires, _ = profile["ExpirationDate"].(time.Time)
	old.IOSApp = IOSApp{Account: account, Icon: old.Icon, Team: team, BundleID: app.BundleID, Name: name, Version: app.Version, Build: app.Build, Expires: expiry, Refreshed: time.Now().UTC()}
	return saveAppRecord(old)
}

// Retain the original IPA, never the signed staging package. This lets a refresh
// run through the complete provisioning and signing pipeline again.
func retainIOSPackage(id, source string) error {
	appsMu.Lock()
	defer appsMu.Unlock()
	record, ok := readAppRecords()[id]
	if !ok {
		return errors.New("Installation history is unavailable")
	}
	target := appRecordPath(id) + ".ipa"
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(target + ".tmp")
		return errors.Join(copyErr, closeErr)
	}
	if err = os.Rename(target+".tmp", target); err != nil {
		return err
	}
	record.Package = filepath.Base(target)
	if info, inspectErr := ipainfo.Inspect(source); inspectErr == nil && len(info.Icon) < 256<<10 {
		record.Icon = info.Icon
	}
	return saveAppRecord(record)
}

// Opting out removes only IPA Loader's managed fallback copy, never the source
// selected in Files. Keep the icon and signed installation proof either way.
func discardIOSPackage(id, source string) error {
	info, _ := ipainfo.Inspect(source)
	appsMu.Lock()
	defer appsMu.Unlock()
	record, ok := readAppRecords()[id]
	if !ok {
		return errors.New("Installation history is unavailable")
	}
	if err := os.Remove(appRecordPath(id) + ".ipa"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	record.Package = ""
	if info != nil && len(info.Icon) < 256<<10 {
		record.Icon = info.Icon
	}
	return saveAppRecord(record)
}
func IOSRefreshPackage(id string) string {
	appsMu.Lock()
	defer appsMu.Unlock()
	record := readAppRecords()[id]
	if record.Package == "" || filepath.Base(record.Package) != record.Package {
		return ""
	}
	path := filepath.Join(appsDirectory(), record.Package)
	if stat, err := os.Stat(path); err == nil && stat.Mode().IsRegular() {
		return path
	}
	return ""
}

// Local history is usable offline. An explicit inventory check reconciles
// deletions and discovers development apps installed by other tools.
func IOSApps(ctx context.Context, check bool) ([]IOSApp, error) {
	appsMu.Lock()
	records := readAppRecords()
	generation := appsGeneration
	appsMu.Unlock()
	var inventory []map[string]any
	var profiles []map[string]any
	var err error
	if check {
		if err = iosnative.ConnectVPN(); err == nil {
			iosSetup.RLock()
			c := iosSetup.config
			udid := ""
			if c != nil {
				udid = c.UDID
			}
			iosSetup.RUnlock()
			if udid != "" {
				inventory, err = hostInstalledApps(ctx, udid)
				if err == nil {
					rawProfiles, profileErr := mobiledevice.WindowsProvisioningProfiles(ctx, udid)
					if profileErr == nil {
						profiles = make([]map[string]any, 0, len(rawProfiles))
						for _, raw := range rawProfiles {
							profile, verifyErr := decodeRefreshProfile(raw)
							if verifyErr != nil {
								continue
							}
							profiles = append(profiles, profile)
						}
					}
				}
			} else {
				err = errors.New("Finish desktop setup to check installed apps")
			}
		}
	}
	apps := map[string]IOSApp{}
	if !check || err != nil {
		for id, record := range records {
			apps[id] = record.IOSApp
		}
	} else {
		appsMu.Lock()
		if appsGeneration != generation {
			// Installation completed while inventory was in flight. Keep the newer
			// local history and let the next check reconcile it.
			for id, record := range readAppRecords() {
				apps[id] = record.IOSApp
			}
		} else {
			apps = reconcileIOSApps(records, inventory, profiles)
			for id, app := range apps {
				record := records[id]
				if record.Version != app.Version || record.Build != app.Build || (record.Team != "" && app.Team != "" && record.Team != app.Team) {
					record.Package = ""
					record.Binding = nil
					record.CheckedAccount = ""
					record.ProfileRefresh = nil
					_ = os.Remove(appRecordPath(id) + ".ipa")
				}
				record.IOSApp = app
				if profiles != nil && !refreshReceiptPresent(record.ProfileRefresh, profiles) {
					record.ProfileRefresh = nil
				}
				_ = saveAppRecord(record)
			}
			// A successful complete inventory is authoritative for removals.
			for id := range records {
				if _, present := apps[id]; !present && id != iosnative.BundleID() {
					_ = os.Remove(appRecordPath(id))
					_ = os.Remove(appRecordPath(id) + ".ipa")
				}
			}
		}
		appsMu.Unlock()
	}
	id := iosnative.BundleID()
	self := IOSApp{BundleID: id, Name: "IPA Loader", Self: true, CanRefresh: true}
	self.Expires, _ = appProfileDates(filepath.Dir(IOSExecutable()))
	iosSetup.RLock()
	if c := iosSetup.config; c != nil {
		self.Account, self.Team = c.Account, c.Team
	}
	iosSetup.RUnlock()
	// A pending self-refresh becomes history only after the installed profile,
	// version and build match its receipt.
	if receipt, ok := confirmedIOSRefresh(); ok {
		self.Refreshed = receipt.RequestedAt
		if !receipt.RequestedAt.IsZero() && receipt.Account != "" {
			self.Account = receipt.Account
		}
	}
	// The installed profile store can renew validity without changing the
	// embedded profile file. Prefer the last verified profile-refresh receipt.
	info, infoErr := readSelfInfo(filepath.Dir(IOSExecutable()))
	if infoErr == nil {
		self.Version, self.Build = stringField(info, "CFBundleShortVersionString"), stringField(info, "CFBundleVersion")
		appsMu.Lock()
		own := readAppRecords()[id]
		appsMu.Unlock()
		if own.Binding != nil && own.Binding.Version == self.Version && own.Binding.Build == self.Build && own.ProfileRefresh != nil && bindingMatchesEmbeddedProfile(filepath.Dir(IOSExecutable()), own.Binding) {
			self.Expires, self.Refreshed, self.Account = own.ProfileRefresh.Expires, own.ProfileRefresh.Refreshed, own.ProfileRefresh.Account
		}
	}
	apps[id] = self
	result := make([]IOSApp, 0, len(apps))
	for _, app := range apps {
		app.CanRefresh = true
		result = append(result, app)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Self != result[j].Self {
			return result[i].Self
		}
		if result[i].Expires.IsZero() != result[j].Expires.IsZero() {
			return !result[i].Expires.IsZero()
		}
		if !result[i].Expires.Equal(result[j].Expires) {
			return result[i].Expires.Before(result[j].Expires)
		}
		return result[i].Name < result[j].Name
	})
	return result, err
}

func IOSRefreshTeam(id string) string {
	appsMu.Lock()
	team := readAppRecords()[id].Team
	appsMu.Unlock()
	if team == "" && id == iosnative.BundleID() {
		iosSetup.RLock()
		if iosSetup.config != nil {
			team = iosSetup.config.Team
		}
		iosSetup.RUnlock()
	}
	return team
}
