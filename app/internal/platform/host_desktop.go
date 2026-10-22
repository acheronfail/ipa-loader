//go:build windows || linux || darwin

package platform

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/signing"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type desktopHost struct {
	team, runtimeRoot string
	runtimeErr        error
	vault             signing.IdentityVault
}

func (h *desktopHost) deviceJSON(e *engine, label string, args ...string) (map[string]any, error) {
	argument := func(name string) string {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == name {
				return args[i+1]
			}
		}
		return ""
	}
	udid := argument("--device")
	switch label {
	case "device-details":
		devices, err := hostDevices(e.ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range devices {
			if d.UDID == udid {
				return map[string]any{"hardwareProperties": map[string]any{"udid": d.UDID}}, nil
			}
		}
		return nil, failure("The selected iPhone disconnected; reconnect it and try again")
	case "device-lock-state":
		locked, err := hostLocked(e.ctx, udid)
		return map[string]any{"passcodeRequired": locked}, err
	case "existing-app", "installed-app":
		records, err := hostInstalledApps(e.ctx, udid)
		if err != nil {
			return nil, err
		}
		wanted := argument("--bundle-id")
		apps := []map[string]any{}
		for _, a := range records {
			id := stringField(a, "CFBundleIdentifier")
			if wanted != "" && id != wanted {
				continue
			}
			team := stringField(mapField(a, "Entitlements"), "com.apple.developer.team-identifier")
			if team == "" {
				team = stringField(a, "TeamIdentifier")
			}
			apps = append(apps, map[string]any{"bundleIdentifier": id, "version": stringField(a, "CFBundleShortVersionString"), "bundleVersion": stringField(a, "CFBundleVersion"), "teamIdentifier": team})
		}
		return map[string]any{"apps": apps}, nil
	}
	return nil, failure("Unsupported device operation")
}

func (h *desktopHost) identities(e *engine) (map[string]bool, error) {
	id, err := h.vault.Load(h.team)
	if errors.Is(err, signing.ErrNoIdentity) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]bool{fingerprint(id.Certificate.Raw): true}, nil
}

func (h *desktopHost) createIdentity(e *engine, client requestClient, session *apple.Session, team string, records []map[string]any) (string, error) {
	pending, err := h.vault.Prepare(team)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(pending.CSR))
	if block == nil {
		return "", failure("Retained signing request is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", failure("Retained signing request is invalid")
	}
	key, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", failure("Unsupported signing key")
	}
	activate := func(records []map[string]any) (string, error) {
		for _, r := range records {
			cert := validCert(r, time.Now())
			if cert == nil {
				continue
			}
			public, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok || public.E != key.E || public.N.Cmp(key.N) != 0 {
				continue
			}
			if err := h.vault.SaveCertificate(team, cert.Raw); err != nil {
				return "", err
			}
			return fingerprint(cert.Raw), nil
		}
		return "", nil
	}
	if id, err := activate(records); id != "" || err != nil {
		return id, err
	}
	if !pending.NeedsSubmission {
		return "", failure("A retained signing key has no matching active certificate; no new CSR submitted")
	}
	if err = e.ctx.Err(); err != nil {
		return "", err
	}
	// Persist uncertainty before any submission bytes can leave this process.
	// A cancelled request which has not reached this point may reuse its CSR.
	if err = h.vault.MarkSubmitted(team, pending.RequestID); err != nil {
		return "", err
	}
	e.emit("Creating a development signing identity")
	if _, err = e.request(client, session, "submitDevelopmentCSR", map[string]any{"csrContent": pending.CSR, "machineId": pending.RequestID, "machineName": "IPA Loader"}, team); err != nil {
		var rejection *apple.Error
		if errors.As(err, &rejection) && rejection.Code == 7460 {
			if retainedErr := h.vault.MarkQuotaRejected(team, pending.RequestID, rejection.Code); retainedErr != nil {
				return "", retainedErr
			}
		}
		return "", err
	}
	response, err := e.request(client, session, "listAllDevelopmentCerts", nil, team)
	if err != nil {
		return "", err
	}
	records, err = recordList(response, "certificates")
	if err != nil {
		return "", err
	}
	id, err := activate(records)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", failure("Issued certificate could not be matched; key retained securely")
	}
	return id, nil
}

func (h *desktopHost) signApp(e *engine, app appInfo, identity, entitlements string) error {
	id, err := h.vault.Load(h.team)
	if err != nil {
		return err
	}
	if fingerprint(id.Certificate.Raw) != identity {
		return failure("signing identity changed")
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(id.PrivateKey)})
	defer clear(key)
	tool := signing.Tool{Profile: filepath.Join(app.Path, "embedded.mobileprovision")}
	for i, object := range app.Embedded {
		if object.Extension && object.Entitlements == "" {
			return failure("App extension has not been provisioned")
		}
		e.emit(fmt.Sprintf("Signing embedded code %d of %d: %s", i+1, len(app.Embedded), filepath.Base(object.Path)))
		tool.Identifier = object.Identifier
		if err = tool.Sign(e.ctx, object.Path, key, id.Certificate.Raw, object.Entitlements); err != nil {
			return err
		}
	}
	tool.Identifier = app.BundleID
	return tool.Sign(e.ctx, app.Path, key, id.Certificate.Raw, entitlements)
}

func (h *desktopHost) install(e *engine, app appInfo, device Device, result *Result, notify func(float64, string)) error {
	notify(.65, "Preparing signed IPA for transfer")
	archive, err := packageSignedApp(e.ctx, app.Path, e.work)
	if err != nil {
		return err
	}
	defer os.Remove(archive)
	client, err := mobiledevice.Open(e.ctx, mobiledevice.Options{UDID: device.UDID, Transport: strings.ToLower(device.Transport)})
	if err != nil {
		return nativeInstallFailure(err, false)
	}
	defer client.Close()
	return e.installStaged(app, device, result, notify, archive, client)
}
