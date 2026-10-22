package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var stagingNamespace = regexp.MustCompile(`^PublicStaging/IPALoader-([a-f0-9]{32})$`)

type stagingRegistry struct{ dir string }

func (e *engine) openStagingRegistry(device Device) (*stagingRegistry, func(), error) {
	config, err := e.configDir()
	if err != nil {
		return nil, nil, failure("Could not locate installation recovery storage")
	}
	dir := filepath.Join(config, "ipa-loader", "device-staging")
	if err = privateDir(dir); err != nil {
		return nil, nil, err
	}
	// One active transport per device, including different apps, prevents this
	// process or another app instance from racing recovery against a submission.
	sum := sha256.Sum256([]byte(device.UDID))
	unlock, err := lockStaging(filepath.Join(dir, hex.EncodeToString(sum[:])+".lock"))
	if err != nil {
		return nil, nil, err
	}
	return &stagingRegistry{dir}, unlock, nil
}

func (r *stagingRegistry) path(record stagingRecord) string {
	match := stagingNamespace.FindStringSubmatch(record.Stage)
	if match == nil || record.Package != record.Stage+"/application.ipa" {
		return ""
	}
	return filepath.Join(r.dir, match[1]+".json")
}

func (r *stagingRegistry) forget(record stagingRecord) {
	if path := r.path(record); path != "" {
		if snapshot, _, err := captureOwned(path); err == nil {
			snapshot.remove(true)
		}
	}
}

func (r *stagingRegistry) save(record stagingRecord) error {
	path := r.path(record)
	if path == "" || record.Format != 1 || record.Created.IsZero() || !validText(record.UDID) || !bundlePattern.MatchString(record.BundleID) {
		return failure("Invalid installation recovery record")
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(r.dir, ".record-")
	if err != nil {
		return failure("Could not write installation recovery state")
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		return failure("Could not persist installation recovery state")
	}
	return nil
}

// Called while holding the device lock. Unsent/terminal packages are safe before
// a retry. An uncertain package is safe only after a later operation for this
// same app/device has reached terminal Complete AND independent confirmation.
// A mere inventory match, time elapsed, or newer local IPA is insufficient.
func (r *stagingRegistry) recover(ctx context.Context, client stagedDevice, current stagingRecord, confirmedLaterInstall bool) int {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return 0
	}
	cleaned := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(r.dir, entry.Name())
		snapshot, body, err := captureOwned(path)
		if err != nil {
			continue
		}
		var previous stagingRecord
		if json.Unmarshal(body, &previous) != nil || previous.Format != 1 || r.path(previous) != path || previous.UDID != current.UDID || previous.BundleID != current.BundleID || previous.Created.IsZero() || !previous.Created.Before(current.Created) || previous.Stage == current.Stage {
			continue
		}
		if previous.MayHaveSubmitted && !previous.Terminal && !confirmedLaterInstall {
			continue
		}
		if !snapshot.same(true) {
			continue
		}
		if client.Remove(ctx, previous.Package) != nil || client.Remove(ctx, previous.Stage) != nil {
			continue
		}
		snapshot.remove(true)
		cleaned++
	}
	return cleaned
}

func freshStagingRecord(stage string, app appInfo, device Device) stagingRecord {
	return stagingRecord{Format: 1, Created: time.Now().UTC(), UDID: device.UDID, Stage: stage, Package: stage + "/application.ipa", BundleID: app.BundleID, Version: app.Version, Build: app.Build}
}
