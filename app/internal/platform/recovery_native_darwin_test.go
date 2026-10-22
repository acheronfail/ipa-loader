//go:build darwin

package platform

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"ipa-loader/app/internal/apple"
)

// Explicitly opt in only when the user has locked the selected test phone.
// Synthetic credentials ensure a regression cannot provision anything.
func TestNativeLockedPhoneStopsBeforeAccountAccess(t *testing.T) {
	fixture := os.Getenv("IPA_LOADER_NATIVE_LOCKED_FIXTURE")
	if fixture == "" {
		t.Skip("requires owned fixture and user-locked selected test phone")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	headerCalled := false
	client := apple.New(func(context.Context) (map[string]string, error) {
		headerCalled = true
		return nil, errors.New("account access forbidden in lock test")
	})
	result, err := Sideload(ctx, client, &apple.Session{Username: "fixture@example.invalid"}, "FIXTURE", fixture, Device{ID: selectedTestDeviceName(t), Name: selectedTestDeviceName(t)}, nil)
	if result.WorkDir != "" {
		defer os.RemoveAll(result.WorkDir)
	}
	if err == nil || !strings.Contains(err.Error(), "Unlock your iPhone") || headerCalled || result.InstallSubmitted || result.Installed {
		t.Fatal("locked phone did not stop before account access and transfer")
	}
}

func TestNativeDisconnectedPhoneStopsBeforeAccountAccess(t *testing.T) {
	fixture := os.Getenv("IPA_LOADER_NATIVE_DISCONNECTED_FIXTURE")
	if fixture == "" {
		t.Skip("requires owned fixture and user-disconnected selected test phone")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// A missing tool or malformed input must not masquerade as evidence that
	// the device-disconnection branch worked.
	e := newControllerTestEngine(ctx, t.TempDir())
	if err := e.checkDeveloperTools(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractIPA(ctx, fixture, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	headerCalled := false
	client := apple.New(func(context.Context) (map[string]string, error) {
		headerCalled = true
		return nil, errors.New("account access forbidden in disconnect test")
	})
	result, err := Sideload(ctx, client, &apple.Session{Username: "fixture@example.invalid"}, "FIXTURE", fixture, Device{ID: selectedTestDeviceName(t), Name: selectedTestDeviceName(t)}, nil)
	if result.WorkDir != "" {
		defer os.RemoveAll(result.WorkDir)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reconnect") || headerCalled || result.InstallSubmitted || result.Installed {
		t.Fatal("disconnected phone did not stop before account access and transfer")
	}
}
