package platform

import (
	"archive/zip"
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"ipa-loader/app/internal/mobiledevice"
	"os"
	"path/filepath"
	"time"
)

type stagedDevice interface {
	NewStage(context.Context) (string, error)
	Upload(context.Context, string, io.Reader, int64, func(int64, int64)) (int64, error)
	Remove(context.Context, string) error
	Upgrade(context.Context, string, int64, ...func(mobiledevice.InstallProgress)) (bool, error)
	Close()
}

type stagingRecord struct {
	Format                                         int
	Created                                        time.Time
	UDID, Stage, Package, BundleID, Version, Build string
	MayHaveSubmitted, Terminal, Cleaned            bool
}

func (e *engine) installNative(app appInfo, device Device, result *Result, notify func(float64, string)) error {
	if e.host == nil {
		return failure("Application host is not configured")
	}
	return e.host.install(e, app, device, result, notify)
}

func (e *engine) installStaged(app appInfo, device Device, result *Result, notify func(float64, string), archive string, client stagedDevice) (err error) {
	file, err := os.Open(archive)
	if err != nil {
		return failure("Could not open signed IPA")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() <= 0 {
		return failure("Signed IPA is not a regular file")
	}
	registry, unlock, err := e.openStagingRegistry(device)
	if err != nil {
		return err
	}
	defer unlock()
	stage, err := client.NewStage(e.ctx)
	if err != nil {
		return nativeInstallFailure(err, false)
	}
	record := freshStagingRecord(stage, app, device)
	journal := filepath.Join(e.work, "device-staging.json")
	save := func() error {
		if err := registry.save(record); err != nil {
			return err
		}
		body, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			return marshalErr
		}
		// Replace atomically so a cancelled/crashed install leaves a complete record.
		temporary := journal + ".tmp"
		if writeErr := os.WriteFile(temporary, body, 0600); writeErr != nil {
			return writeErr
		}
		return os.Rename(temporary, journal)
	}
	defer func() {
		// iOS can finish after local observation is cancelled. Keep its package until
		// terminal completion or an independently verified newer recovery install.
		if record.MayHaveSubmitted && !record.Terminal {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if client.Remove(cleanup, record.Package) == nil && client.Remove(cleanup, stage) == nil {
			record.Cleaned = true
			if save() == nil {
				registry.forget(record)
			}
		}
	}()
	if err = save(); err != nil {
		return failure("Could not record private device staging")
	}
	if registry.recover(e.ctx, client, record, false) > 0 {
		notify(.7, "Removed completed or incomplete packages from an earlier attempt")
	}
	var lastProgress time.Time
	if _, err = client.Upload(e.ctx, record.Package, file, stat.Size(), func(sent, total int64) {
		if sent != total && time.Since(lastProgress) < 100*time.Millisecond {
			return
		}
		lastProgress = time.Now()
		notify(.7+.14*float64(sent)/float64(total), fmt.Sprintf("Sending app to iPhone · %.1f of %.1f MB", float64(sent)/1e6, float64(total)/1e6))
	}); err != nil {
		return nativeInstallFailure(err, false)
	}
	// Persist uncertainty BEFORE any submission bytes can leave this process.
	record.MayHaveSubmitted = true
	if err = save(); err != nil {
		record.MayHaveSubmitted = false
		return failure("Could not record installation recovery state")
	}
	submitted, upgradeErr := client.Upgrade(e.ctx, record.Package, stat.Size(), func(p mobiledevice.InstallProgress) {
		if p.Submitted {
			result.InstallSubmitted = true
		}
		if p.Percent < 0 {
			notify(.84, "Installing on iPhone · close the app on your iPhone if installation waits")
		} else {
			notify(.84+.13*float64(p.Percent)/100, fmt.Sprintf("Installing on iPhone · %d%%", p.Percent))
		}
	})
	result.InstallSubmitted = result.InstallSubmitted || submitted
	var rejection *mobiledevice.InstallationRejectionError
	rejected := errors.As(upgradeErr, &rejection)
	if rejected {
		// Device descriptions may contain private paths and identifiers. Retain
		// them in the private work directory, never in the UI error or progress.
		diagnostic, diagnosticErr := os.OpenFile(filepath.Join(e.work, "installation-rejection.plist"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if diagnosticErr == nil {
			diagnosticErr = rejection.WriteDiagnostics(diagnostic)
			closeErr := diagnostic.Close()
			if diagnosticErr == nil {
				diagnosticErr = closeErr
			}
		}
		if diagnosticErr != nil {
			upgradeErr = fmt.Errorf("%w (could not save private device diagnostics)", upgradeErr)
		}
	}
	record.MayHaveSubmitted = result.InstallSubmitted
	record.Terminal = upgradeErr == nil || rejected
	if saveErr := save(); saveErr != nil && upgradeErr == nil {
		return failure("Could not update private installation recovery state")
	}
	if upgradeErr != nil {
		return nativeInstallFailure(upgradeErr, result.InstallSubmitted)
	}
	if err = e.confirmInstalled(app, device, result, notify); err != nil {
		return err
	}
	if registry.recover(e.ctx, client, record, true) > 0 {
		notify(1, "Installation confirmed · earlier staging packages cleaned")
	}
	return nil
}

func nativeInstallFailure(err error, submitted bool) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var rejection *mobiledevice.InstallationRejectionError
	if errors.As(err, &rejection) {
		return err
	}
	if errors.Is(err, mobiledevice.ErrUnavailable) {
		return fmt.Errorf("Device service is unavailable; check its installation and connection (%w)", err)
	}
	if submitted {
		return fmt.Errorf("Installation was not confirmed. Reconnect your iPhone and unlock it. It may still finish installing; check it before retrying (%w)", err)
	}
	return fmt.Errorf("Reconnect your iPhone, unlock it, and retry. The app was not submitted for installation (%w)", err)
}

// Stream a compressed IPA. Storing expanded assets can unnecessarily push a
// package past the classic ZIP size limit and doubles transfer/storage costs
// for large, compressible apps. Keep ZIP64 support for apps that still need it.
func packageSignedApp(ctx context.Context, appPath, work string) (dest string, err error) {
	var required uint64
	err = filepath.WalkDir(appPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return failure("Signed app contains an unsupported file type")
		}
		// Bound header overhead as well as file data, with checked addition.
		// Include room for DEFLATE block overhead even for incompressible data.
		size := uint64(info.Size()) + uint64(info.Size())/1000 + uint64(len(path))*2 + 1024
		if ^uint64(0)-required < size {
			return failure("Signed app is too large for this filesystem")
		}
		required += size
		return nil
	})
	if err != nil {
		return "", err
	}
	if err = checkExtractionSpace(work, required); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(work, "signed-*.ipa")
	if err != nil {
		return "", failure("Could not create signed IPA")
	}
	dest = file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(dest)
		}
	}()
	writer := zip.NewWriter(file)
	writer.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestSpeed)
	})
	err = filepath.WalkDir(appPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return failure("Signed app contains an unsupported file type")
		}
		relative, err := filepath.Rel(filepath.Dir(appPath), path)
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		mode, err := signedArchiveMode(path, info)
		if err != nil {
			return err
		}
		header.SetMode(mode)
		header.Name, header.Method = "Payload/"+filepath.ToSlash(relative), zip.Deflate
		if info.IsDir() {
			header.Name += "/"
		}
		member, err := writer.CreateHeader(header)
		if err != nil || info.IsDir() {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(member, contextReader{ctx, input})
		input.Close()
		if copyErr != nil {
			return copyErr
		}
		if n != info.Size() {
			return failure("Signed app changed while packaging")
		}
		return nil
	})
	zipErr, closeErr := writer.Close(), file.Close()
	if err == nil {
		err = zipErr
	}
	if err == nil {
		err = closeErr
	}
	return dest, err
}
