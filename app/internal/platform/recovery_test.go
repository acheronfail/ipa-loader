package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDeviceLockGate(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   map[string]any
		blocked bool
	}{
		{"unlocked", map[string]any{"passcodeRequired": false, "unlockedSinceBoot": true}, false},
		{"locked", map[string]any{"passcodeRequired": true, "unlockedSinceBoot": true}, true},
		{"before first unlock", map[string]any{"passcodeRequired": true, "unlockedSinceBoot": false}, true},
		{"missing", map[string]any{}, true},
		{"wrong type", map[string]any{"passcodeRequired": "false"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if (validateLockState(test.state) != nil) != test.blocked {
				t.Fatal("unsafe lock gate result")
			}
		})
	}
}

func TestLockCheckCancellationAndDisconnectedDevice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := newControllerTestEngine(ctx, t.TempDir())
	e.host.(*controllerTestHost).device = func(string, ...string) (map[string]any, error) {
		t.Fatal("cancelled check touched device")
		return nil, nil
	}
	cancel()
	if err := e.checkDeviceUnlocked(Device{ID: "owned-phone"}); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation")
	}
	e = newControllerTestEngine(context.Background(), t.TempDir())
	e.host.(*controllerTestHost).device = func(string, ...string) (map[string]any, error) {
		return nil, errors.New("device disconnected")
	}
	if err := e.checkDeviceUnlocked(Device{ID: "owned-phone"}); err == nil || !strings.Contains(err.Error(), "reconnect") {
		t.Fatal("disconnect not explained")
	}
}

func TestLockCheckUsesDeviceResult(t *testing.T) {
	e := newControllerTestEngine(context.Background(), t.TempDir())
	e.host.(*controllerTestHost).device = func(label string, args ...string) (map[string]any, error) {
		if label != "device-lock-state" || strings.Join(args, " ") != "device info lockState --device owned-phone" {
			t.Fatal("wrong device operation")
		}
		return map[string]any{"passcodeRequired": true}, nil
	}
	if err := e.checkDeviceUnlocked(Device{ID: "owned-phone"}); err == nil || !strings.Contains(err.Error(), "Unlock") {
		t.Fatal("locked device was not blocked")
	}
}
