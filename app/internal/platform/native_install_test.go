package platform

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"ipa-loader/app/internal/mobiledevice"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stagedFake struct {
	failUpload, failUpgrade bool
	rejectUpgrade           bool
	removed                 int
}

func (*stagedFake) NewStage(context.Context) (string, error) {
	return "PublicStaging/IPALoader-0123456789abcdef0123456789abcdef", nil
}
func (f *stagedFake) Upload(_ context.Context, _ string, r io.Reader, total int64, p func(int64, int64)) (int64, error) {
	if f.failUpload {
		p(2, total)
		return 2, context.Canceled
	}
	n, err := io.Copy(io.Discard, r)
	p(n, total)
	return n, err
}
func (f *stagedFake) Upgrade(_ context.Context, _ string, _ int64, p ...func(mobiledevice.InstallProgress)) (bool, error) {
	p[0](mobiledevice.InstallProgress{Submitted: true, Percent: 5})
	if f.rejectUpgrade {
		return true, &mobiledevice.InstallationRejectionError{}
	}
	if f.failUpgrade {
		return true, context.Canceled
	}
	return true, nil
}
func (f *stagedFake) Remove(context.Context, string) error { f.removed++; return nil }
func (*stagedFake) Close()                                 {}

func TestNativeInstallStagingLifecycle(t *testing.T) {
	for _, kind := range []string{"success", "upload cancelled", "observation cancelled", "inventory mismatch", "device rejection"} {
		t.Run(kind, func(t *testing.T) {
			work := testPrivateTempDir(t)
			archive := filepath.Join(work, "signed.ipa")
			if err := os.WriteFile(archive, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			e := newControllerTestEngine(context.Background(), work)
			config, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			e.configDir = func() (string, error) { return config, nil }
			e.host.(*controllerTestHost).device = func(label string, args ...string) (map[string]any, error) {
				if label != "installed-app" {
					t.Fatal("unexpected device operation", label)
				}
				build := "8"
				if kind == "inventory mismatch" {
					build = "7"
				}
				return map[string]any{"apps": []any{map[string]any{"bundleIdentifier": "org.example.owned", "version": "1", "bundleVersion": build}}}, nil
			}
			fake := &stagedFake{failUpload: kind == "upload cancelled", failUpgrade: kind == "observation cancelled", rejectUpgrade: kind == "device rejection"}
			result := Result{}
			completed := false
			err = e.installStaged(appInfo{BundleID: "org.example.owned", Version: "1", Build: "8"}, Device{UDID: "private-phone"}, &result, func(f float64, _ string) { completed = completed || f == 1 }, archive, fake)
			success := kind == "success"
			if (err == nil) != success || result.Installed != success || completed != success {
				t.Fatal("unconfirmed installation reported success")
			}
			if result.InstallSubmitted == (kind == "upload cancelled") {
				t.Fatal("submission state incorrect")
			}
			body, readErr := os.ReadFile(filepath.Join(work, "device-staging.json"))
			var record stagingRecord
			if readErr != nil || json.Unmarshal(body, &record) != nil {
				t.Fatal("missing recovery journal")
			}
			uncertain := kind == "observation cancelled"
			if record.Cleaned == uncertain || (fake.removed == 0) != uncertain {
				t.Fatal("unsafe or missing cleanup")
			}
			if uncertain && (!record.MayHaveSubmitted || record.Terminal) {
				t.Fatal("lost uncertainty")
			}
			if kind == "device rejection" {
				if !record.Terminal || !record.Cleaned || strings.Contains(err.Error(), "Reconnect") {
					t.Fatal("explicit rejection was treated as a connection loss")
				}
				path := filepath.Join(work, "installation-rejection.plist")
				info, statErr := os.Stat(path)
				if statErr != nil || info.Size() == 0 || !privateFile(path, info) {
					t.Fatal("device rejection diagnostics missing or not private", statErr)
				}
			}
			info, _ := os.Stat(filepath.Join(work, "device-staging.json"))
			if !privateFile(filepath.Join(work, "device-staging.json"), info) {
				t.Fatal("journal not private")
			}
		})
	}
}

func TestSignedIPAPackaging(t *testing.T) {
	work := t.TempDir()
	app := filepath.Join(work, "Test.app")
	if err := os.MkdirAll(filepath.Join(app, "Frameworks"), 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(app, "Test")
	if err := os.WriteFile(binary, thin(), 0755); err != nil {
		t.Fatal(err)
	}
	asset := strings.Repeat("dictionary entry\n", 65536)
	if err := os.WriteFile(filepath.Join(app, "dictionary"), []byte(asset), 0644); err != nil {
		t.Fatal(err)
	}
	archive, err := packageSignedApp(context.Background(), app, work)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	found := false
	for _, member := range reader.File {
		if !strings.HasPrefix(member.Name, "Payload/Test.app/") {
			t.Fatal("invalid IPA member")
		}
		if member.Name == "Payload/Test.app/Test" {
			r, _ := member.Open()
			body, _ := io.ReadAll(r)
			r.Close()
			if string(body) != string(thin()) || member.Mode().Perm() != 0755 {
				t.Fatal("lost bytes or executable permission")
			}
			found = true
		}
		if member.Name == "Payload/Test.app/dictionary" {
			r, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r)
			r.Close()
			if err != nil || string(body) != asset || member.Method != zip.Deflate || member.CompressedSize64 >= member.UncompressedSize64/2 {
				t.Fatal("compressible assets expanded during IPA packaging", err)
			}
		}
	}
	if !found {
		t.Fatal("missing executable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = packageSignedApp(ctx, app, work); !errors.Is(err, context.Canceled) {
		t.Fatal("packaging ignored cancellation")
	}
	t.Run("reject symlink", func(t *testing.T) {
		testSymlink(t, binary, filepath.Join(app, "link"))
		if _, err = packageSignedApp(context.Background(), app, work); err == nil {
			t.Fatal("symlink accepted")
		}
	})
}
