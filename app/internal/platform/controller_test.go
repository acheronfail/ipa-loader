package platform

import (
	"context"
	"ipa-loader/app/internal/apple"
	"testing"
)

type controllerTestHost struct {
	device   func(string, ...string) (map[string]any, error)
	identity func() (map[string]bool, error)
}

func newControllerTestEngine(ctx context.Context, work string) *engine {
	e := newEngine(ctx, work)
	e.host = &controllerTestHost{}
	return e
}
func (h *controllerTestHost) deviceJSON(e *engine, label string, args ...string) (map[string]any, error) {
	if h.device == nil {
		return nil, failure("Unexpected test device operation")
	}
	return h.device(label, args...)
}
func (h *controllerTestHost) identities(*engine) (map[string]bool, error) {
	if h.identity == nil {
		return nil, failure("Unexpected test identity lookup")
	}
	return h.identity()
}
func (*controllerTestHost) createIdentity(*engine, requestClient, *apple.Session, string, []map[string]any) (string, error) {
	return "", failure("Unexpected test certificate issuance")
}
func (*controllerTestHost) signApp(*engine, appInfo, string, string) error {
	return failure("Unexpected test signing operation")
}
func (*controllerTestHost) checkTools(e *engine) error { return e.ctx.Err() }
func (*controllerTestHost) sharingLibrary(e *engine) (string, error) {
	return e.buildDarwinSharingLibrary()
}
func (*controllerTestHost) install(*engine, appInfo, Device, *Result, func(float64, string)) error {
	return failure("Unexpected test installation")
}

func TestUnconfiguredHostCannotInvokeFallbackTools(t *testing.T) {
	e := newEngine(context.Background(), t.TempDir())
	e.run = func(name string, _ ...string) ([]byte, []byte, error) {
		t.Fatalf("unconfigured host launched %s", name)
		return nil, nil, nil
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{"device", func() error { _, err := e.deviceJSON("device-details"); return err }},
		{"identity lookup", func() error { _, err := e.identities(); return err }},
		{"identity creation", func() error { _, err := e.createOrRecoverIdentity(nil, nil, "TEAM", nil); return err }},
		{"signing", func() error { return e.signApp(appInfo{}, "", "") }},
		{"installation", func() error { return e.installNative(appInfo{}, Device{}, &Result{}, nil) }},
		{"sharing", func() error { _, err := e.buildSharingLibrary(); return err }},
		{"preflight", func() error { return e.checkInstallDevice(Device{}) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err == nil {
				t.Fatal("unconfigured host accepted operation")
			}
		})
	}
}
