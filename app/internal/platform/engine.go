package platform

import (
	"bytes"
	"context"
	"ipa-loader/app/internal/apple"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type requestClient interface {
	Request(context.Context, *apple.Session, string, map[string]any, string) (map[string]any, error)
}
type engine struct {
	networkRequests map[string]networkRequest
	host            hostBackend
	ctx             context.Context
	work            string
	run             func(string, ...string) ([]byte, []byte, error)
	message         func(string)
	configDir       func() (string, error)
	decodeProfile   func(string) ([]byte, error)
}

func newEngine(ctx context.Context, work string) *engine {
	e := &engine{ctx: ctx, work: work, configDir: os.UserConfigDir, decodeProfile: decodeProfile}
	e.run = func(name string, args ...string) ([]byte, []byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		configureHostCommand(cmd)
		var out, err bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &err
		failure := cmd.Run()
		return out.Bytes(), err.Bytes(), failure
	}
	return e
}
func (e *engine) command(label, name string, args ...string) ([]byte, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	out, diag, err := e.run(name, args...)
	_ = os.WriteFile(filepath.Join(e.work, label+".log"), append(append([]byte{}, out...), diag...), 0600)
	if err != nil {
		if e.ctx.Err() != nil {
			return nil, e.ctx.Err()
		}
		return nil, failure(label + " failed; private diagnostics retained")
	}
	return out, nil
}
func (e *engine) deviceJSON(label string, args ...string) (map[string]any, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	if e.host == nil {
		return nil, failure("Application host is not configured")
	}
	return e.host.deviceJSON(e, label, args...)
}

func (e *engine) identities() (map[string]bool, error) {
	if e.host == nil {
		return nil, failure("Application host is not configured")
	}
	return e.host.identities(e)
}

func (e *engine) request(client requestClient, session *apple.Session, action string, params map[string]any, team string) (map[string]any, error) {
	if e.ctx.Err() != nil {
		return nil, e.ctx.Err()
	}
	r, err := client.Request(e.ctx, session, action, params, team)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, failure("Developer service returned an invalid response")
	}
	return r, nil
}
func (e *engine) emit(message string) {
	if e.message != nil {
		e.message(message)
	}
}

func (e *engine) signApp(app appInfo, identity, entitlements string) error {
	if e.host == nil {
		return failure("Application host is not configured")
	}
	return e.host.signApp(e, app, identity, entitlements)
}

func (e *engine) provision(client requestClient, session *apple.Session, team, udid, bundle string, appGroups ...string) (string, []byte, error) {
	e.emit("Checking saved signing identities")
	identities, err := e.identities()
	if err != nil {
		return "", nil, err
	}
	r, err := e.request(client, session, "listAllDevelopmentCerts", nil, team)
	if err != nil {
		return "", nil, err
	}
	records, err := recordList(r, "certificates")
	if err != nil {
		return "", nil, err
	}
	cert := chooseCertificate(records, identities, time.Now())
	identity := ""
	if cert != nil {
		e.emit("Reusing an existing signing identity")
		identity = fingerprint(cert["certContent"].([]byte))
	} else {
		identity, err = e.createOrRecoverIdentity(client, session, team, records)
		if err != nil {
			return "", nil, err
		}
	}
	e.emit("Checking registered iPhone")
	r, err = e.request(client, session, "listDevices", nil, team)
	if err != nil {
		return "", nil, err
	}
	devices, err := recordList(r, "devices")
	if err != nil {
		return "", nil, err
	}
	found := false
	for _, d := range devices {
		if stringField(d, "deviceNumber") == udid {
			found = true
		}
	}
	if !found {
		e.emit("Registering iPhone with the selected team")
		if _, err = e.request(client, session, "addDevice", map[string]any{"deviceNumber": udid, "name": "IPA Loader iPhone"}, team); err != nil {
			return "", nil, err
		}
	}
	data, err := e.provisionAppProfile(client, session, team, bundle, appGroups...)
	return identity, data, err
}

func (e *engine) provisionAppProfile(client requestClient, session *apple.Session, team, bundle string, appGroups ...string) ([]byte, error) {
	e.emit("Checking app identifier")
	r, err := e.request(client, session, "listAppIds", nil, team)
	if err != nil {
		return nil, err
	}
	apps, err := recordList(r, "appIds")
	if err != nil {
		return nil, err
	}
	appID := ""
	appRecord := map[string]any{}
	matches := 0
	for _, a := range apps {
		if stringField(a, "identifier") == bundle {
			matches++
			if matches > 1 {
				return nil, failure("Developer service returned duplicate App IDs")
			}
			appID = stringField(a, "appIdId")
			appRecord = a
			if !validText(appID) {
				return nil, failure("Developer service returned an invalid App ID")
			}
		}
	}
	if appID == "" {
		e.emit("Registering app identifier")
		r, err = e.request(client, session, "addAppId", map[string]any{"identifier": bundle, "name": "IPA Loader"}, team)
		if err != nil {
			return nil, err
		}
		a, _ := r["appId"].(map[string]any)
		appID = stringField(a, "appIdId")
		appRecord = a
	}
	if !validText(appID) {
		return nil, failure("Developer service returned an invalid App ID")
	}
	if len(appGroups) > 0 {
		// Determine account type from an authenticated profile before attempting
		// app-group portal operations, which Personal Teams cannot perform.
		data, err := e.downloadAppProfile(client, session, team, appID)
		if err != nil {
			return nil, err
		}
		file, err := os.CreateTemp(e.work, "account-profile-*.mobileprovision")
		if err != nil {
			return nil, failure("Could not inspect provisioning account type")
		}
		path := file.Name()
		defer os.Remove(path)
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return nil, failure("Could not inspect provisioning account type")
		}
		decoded, err := e.decodeProfile(path)
		if err != nil {
			return nil, failure("Account provisioning profile CMS integrity did not verify")
		}
		p, err := dictionary(decoded)
		if err != nil {
			return nil, err
		}
		if teams := textList(p["TeamIdentifier"]); len(teams) != 1 || teams[0] != team {
			return nil, failure("Account provisioning profile belongs to a different team")
		}
		if value, present := p["LocalProvision"]; present {
			local, ok := value.(bool)
			if !ok {
				return nil, failure("Provisioning profile has an invalid account type")
			}
			if local {
				e.emit("Free account: using app-local storage instead of shared app groups")
				return data, nil
			}
		}
	}
	enabled := contains(textList(appRecord["enabledFeatures"]), "APG3427HIY") && mapField(appRecord, "features")["APG3427HIY"] == true
	if err = e.provisionSharingGroups(client, session, team, appID, appGroups, enabled); err != nil {
		return nil, err
	}
	if e.networkRequests[bundle].PacketTunnel {
		enabledNetwork := contains(textList(appRecord["enabledFeatures"]), "NWEXT04537") && mapField(appRecord, "features")["NWEXT04537"] == true
		if !enabledNetwork {
			e.emit("Enabling packet tunnel capability")
			if _, err = e.request(client, session, "updateAppId", map[string]any{"appIdId": appID, "NWEXT04537": true}, team); err != nil {
				return nil, err
			}
		}
	}
	return e.downloadAppProfile(client, session, team, appID)
}

func (e *engine) downloadAppProfile(client requestClient, session *apple.Session, team, appID string) ([]byte, error) {
	e.emit("Downloading provisioning profile")
	r, err := e.request(client, session, "downloadTeamProvisioningProfile", map[string]any{"appIdId": appID}, team)
	if err != nil {
		return nil, err
	}
	p, _ := r["provisioningProfile"].(map[string]any)
	data, ok := p["encodedProfile"].([]byte)
	if !ok || len(data) == 0 || len(data) > 16<<20 {
		return nil, failure("Developer service returned an invalid profile")
	}
	return data, nil
}
func privateDir(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		if info, e := os.Lstat(p); e == nil && info.Mode()&os.ModeSymlink != 0 {
			return failure("Private signing path cannot contain symlinks")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return ensurePrivateDirectory(path)
}
func (e *engine) createOrRecoverIdentity(client requestClient, session *apple.Session, team string, records []map[string]any) (string, error) {
	if e.host == nil {
		return "", failure("Application host is not configured")
	}
	return e.host.createIdentity(e, client, session, team, records)
}

func (e *engine) checkDeveloperTools() error {
	if e.host == nil {
		return failure("Application host is not configured")
	}
	return e.host.checkTools(e)
}
