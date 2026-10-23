//go:build ios

package platform

import (
	"context"
	"errors"
	"path/filepath"

	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/iosnative"
	"ipa-loader/app/internal/iosupdate"
	"ipa-loader/app/internal/ipa"
)

type selfUpdateKey struct{}

func iosUpdateCache() string {
	return filepath.Join(iosnative.Home(), "Library", "Application Support", "ipa-loader", "updates")
}
func IOSLoaderVersion() string {
	info, err := readSelfInfo(filepath.Dir(IOSExecutable()))
	if err != nil {
		return ""
	}
	return stringField(info, "CFBundleShortVersionString")
}
func IOSLoaderTeam() string {
	iosSetup.RLock()
	defer iosSetup.RUnlock()
	if iosSetup.config == nil {
		return ""
	}
	return iosSetup.config.Team
}

// UpdateIOSLoader keeps pairing/bootstrap credentials intact and stages the
// verified original before installation can terminate this process.
func UpdateIOSLoader(ctx context.Context, client *apple.Client, session *apple.Session, team, path string, device Device, progress func(Progress)) (Result, error) {
	iosSetup.RLock()
	c := iosSetup.config
	iosSetup.RUnlock()
	if c == nil || session == nil {
		return Result{}, errors.New("Finish desktop setup and sign in before updating IPA Loader")
	}
	if team != c.Team || device.UDID != c.UDID || c.Account != "" && accounts.Key(session.Username) != accounts.Key(c.Account) {
		return Result{}, errors.New("Update IPA Loader using its original Apple Account, developer team and iPhone")
	}
	info, err := ipa.Inspect(path)
	if err != nil {
		return Result{}, err
	}
	newer, err := iosupdate.Newer(info.Version, IOSLoaderVersion())
	if err != nil {
		return Result{}, err
	}
	if !newer {
		return Result{}, errors.New("This IPA Loader update is not newer than the installed app")
	}
	if err = iosupdate.ValidatePackage(path, info.Version, iosnative.HasVPN()); err != nil {
		return Result{}, err
	}
	saved, err := iosupdate.SavePackage(ctx, iosUpdateCache(), path)
	if err != nil {
		return Result{}, err
	}
	return Sideload(context.WithValue(ctx, selfUpdateKey{}, true), client, session, team, saved, device, progress)
}

func iosSelfRefreshPackage() (string, error) {
	info, err := readSelfInfo(filepath.Dir(IOSExecutable()))
	if err != nil {
		return "", err
	}
	version, build := stringField(info, "CFBundleShortVersionString"), stringField(info, "CFBundleVersion")
	return iosupdate.RefreshPackage(iosUpdateCache(), selfIPAPath(), version, build)
}
