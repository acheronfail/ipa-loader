package iosupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ipa-loader/app/internal/bootstrap"
	"ipa-loader/app/internal/ipa"
)

func ValidatePackage(path, version string, builtin bool) error {
	info, err := ipa.Inspect(path)
	if err != nil {
		return err
	}
	if info.BundleID != bootstrap.BundleID || info.Version != version {
		return errors.New("The update IPA does not match the IPA Loader release")
	}
	z, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer z.Close()
	tunnel := false
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, "/PlugIns/IPALoaderTunnel.appex/Info.plist") {
			tunnel = true
		}
	}
	if tunnel != builtin {
		return errors.New("The update IPA does not match this installation’s VPN variant")
	}
	return nil
}

type cachedPackage struct{ Version, Build, SHA256 string }

func cacheKey(version, build string) string {
	sum := sha256.Sum256([]byte(version + "\x00" + build))
	return hex.EncodeToString(sum[:]) + ".json"
}

// SavePackage makes the original available for self-refresh before submission:
// iOS may terminate this process before installation returns. Content-addressed
// files and atomic records keep a failed update from replacing the old fallback.
func SavePackage(ctx context.Context, root, path string) (string, error) {
	info, err := ipa.Inspect(path)
	if err != nil {
		return "", err
	}
	if info.BundleID != bootstrap.BundleID {
		return "", errors.New("Not an IPA Loader package")
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	file, err := os.CreateTemp(root, ".package-")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(input, maxIPA+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n > maxIPA {
		return "", errors.New("IPA Loader package is too large")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	record := cachedPackage{Version: info.Version, Build: info.Build, SHA256: hex.EncodeToString(hash.Sum(nil))}
	target := filepath.Join(root, record.SHA256+".ipa")
	if err = os.Rename(file.Name(), target); err != nil {
		return "", err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	meta, err := os.CreateTemp(root, ".record-")
	if err != nil {
		return "", err
	}
	defer os.Remove(meta.Name())
	_, writeErr := meta.Write(raw)
	syncErr = meta.Sync()
	closeErr = meta.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err = os.Rename(meta.Name(), filepath.Join(root, cacheKey(info.Version, info.Build))); err != nil {
		return "", err
	}
	return target, nil
}

func SavedPackage(root, version, build string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, cacheKey(version, build)))
	if err != nil {
		return "", err
	}
	var record cachedPackage
	if len(raw) > 4096 || json.Unmarshal(raw, &record) != nil || record.Version != version || record.Build != build {
		return "", errors.New("Invalid saved update record")
	}
	digest, err := hex.DecodeString(record.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return "", errors.New("Invalid saved update digest")
	}
	path := filepath.Join(root, record.SHA256+".ipa")
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxIPA+1))
	if err != nil {
		return "", err
	}
	if n > maxIPA || hex.EncodeToString(hash.Sum(nil)) != record.SHA256 {
		return "", errors.New("The saved update IPA has changed")
	}
	return path, nil
}

// RefreshPackage selects only an IPA matching the running app. A staged future
// update cannot downgrade or change the fallback for a failed installation.
func RefreshPackage(root, original, version, build string) (string, error) {
	path, err := SavedPackage(root, version, build)
	if err == nil {
		return path, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	info, err := ipa.Inspect(original)
	if err != nil {
		return "", err
	}
	if info.Version != version || info.Build != build || info.BundleID != bootstrap.BundleID {
		return "", errors.New("This version’s self-refresh IPA is missing. Update or repeat desktop setup before full self-refresh")
	}
	return original, nil
}
