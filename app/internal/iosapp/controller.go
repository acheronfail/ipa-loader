// Package iosapp coordinates the native iPhone interface. UIKit owns navigation;
// this package owns authentication and one cancellable operation at a time.
package iosapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

type Action struct{ Kind, Value, Username, Password string }
type State struct {
	Authenticated, Busy                                     bool
	VPNAvailable, VPNConnected, VPNBusy, VPNRequested       bool
	VPNMessage                                              string
	EligibleRefreshes                                       int
	OperationID                                             uint64
	Username, TeamID, Quota, AccountMessage, SignInUsername string
	Accounts                                                []string
	Teams                                                   []apple.Team
	Operation, Target, Message                              string
	Fraction                                                float64
	Failed                                                  bool
	Cancelled                                               bool
	Logs                                                    []string
	Results                                                 []string
	Certificates                                            []apple.DevelopmentCertificate
}
type Services struct {
	Accounts        *accounts.Store
	Login           func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error)
	Teams           func(context.Context, *apple.Session) ([]apple.Team, error)
	Device          func(context.Context) (platform.Device, error)
	Refresh         func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error)
	Install         func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error)
	RefreshTeam     func(string) string
	ChooseIPA       func() (string, error)
	ConfirmIPA      func(*ipa.Info) (bool, bool, error)
	Ask             func(apple.Challenge) (string, error)
	ConfirmFallback func(string) bool
	Connection      func() error
	Certificates    func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error)
	Revoke          func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error
	Publish         func(State)
	ResetVPN        func()
	VPNState        func() (bool, bool)
	SetVPN          func(bool) error
	Reload          func()
}
type Controller struct {
	mu           sync.Mutex
	services     Services
	state        State
	session      *apple.Session
	saved        []*apple.Session
	cancel       context.CancelFunc
	certificates []apple.DevelopmentCertificate
	apps         []platform.IOSApp
}

func accountOperation(operation string) bool { return operation == "account" || operation == "signin" }

func New(s Services) *Controller { return &Controller{services: s} }
func (c *Controller) Snapshot() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.EligibleRefreshes = len(c.eligibleLocked())
	s.Accounts = append([]string{}, s.Accounts...)
	s.Teams = append([]apple.Team{}, s.Teams...)
	s.Logs = append([]string{}, s.Logs...)
	s.Results = append([]string{}, s.Results...)
	s.Certificates = append([]apple.DevelopmentCertificate{}, s.Certificates...)
	return s
}
func (c *Controller) publish() {
	if c.services.Publish != nil {
		c.services.Publish(c.Snapshot())
	}
}
func (c *Controller) begin(auth bool, operation, target string) (context.Context, bool) {
	c.mu.Lock()
	if c.state.Busy || c.state.VPNBusy || (auth && c.session == nil) {
		c.mu.Unlock()
		c.publish()
		return nil, false
	}
	if (operation == "refresh" || operation == "install" || operation == "refreshall") && c.state.VPNAvailable && !c.state.VPNConnected {
		c.mu.Unlock()
		c.publish()
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.state.Busy = true
	c.state.Operation = operation
	c.state.OperationID++
	if !accountOperation(operation) {
		c.state.Target = target
		c.state.Message = "Preparing…"
		c.state.Fraction = 0
		c.state.Failed = false
		c.state.Cancelled = false
		c.state.Logs = nil
		c.state.Results = nil
	}
	c.mu.Unlock()
	c.publish()
	return ctx, true
}
func (c *Controller) end(ctx context.Context, err error) {
	c.mu.Lock()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	wasCanceled := ctx.Err() != nil
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.state.Busy = false
	var portalError *apple.Error
	if (c.state.Operation == "signin" && wasCanceled && !c.state.Authenticated) || (c.state.Operation != "signin" && errors.As(err, &portalError) && portalError.Code == 1100) {
		c.session = nil
		c.state.Authenticated = false
		c.state.Teams = nil
		c.state.TeamID = ""
		c.state.Quota = ""
		c.state.Certificates = nil
		c.certificates = nil
	}
	if err != nil {
		message := err.Error()
		if errors.Is(err, context.Canceled) {
			c.state.Cancelled = true
			c.state.Failed = false
			c.state.Message = ""
			c.state.AccountMessage = ""
			c.mu.Unlock()
			c.publish()
			return
		}
		if accountOperation(c.state.Operation) {
			c.state.AccountMessage = message
		} else {
			c.state.Message = message
			c.state.Failed = true
		}
	}
	c.mu.Unlock()
	c.publish()
}
func (c *Controller) progress(p platform.Progress) {
	c.mu.Lock()
	c.state.Message = p.Message
	c.state.Fraction = p.Fraction
	c.state.Logs = append(c.state.Logs, p.Message)
	if len(c.state.Logs) > 100 {
		c.state.Logs = c.state.Logs[1:]
	}
	c.mu.Unlock()
	c.publish()
}
func (c *Controller) Handle(a Action) {
	if a.Kind == "cancel" {
		c.mu.Lock()
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Unlock()
		return
	}
	switch a.Kind {
	case "start":
		c.updateVPN()
		c.restore()
	case "vpnstatus":
		c.updateVPN()
	case "vpnconfiguration":
		if c.services.ResetVPN != nil {
			c.services.ResetVPN()
		}
		c.updateVPN()
	case "vpn":
		c.setVPN(a.Value == "on")
	case "refreshall":
		c.refreshAll()
	case "login":
		c.login(a.Username, a.Password)
	case "resume":
		c.resume(a.Value)
	case "signout":
		c.signOut()
	case "forget":
		c.forget(a.Value)
	case "team":
		c.selectTeam(a.Value)
	case "refresh":
		c.operate(a.Value)
	case "import":
		c.operate("")
	case "connection":
		c.connection()
	case "certificates":
		c.manageCertificates("")
	case "revoke":
		c.manageCertificates(a.Value)
	}
}
func (c *Controller) readSaved() error {
	if c.services.Accounts == nil {
		return nil
	}
	snapshot, err := c.services.Accounts.Load()
	if err != nil {
		return errors.New("Your saved sign-in couldn’t be opened. Unlock your iPhone and sign in again.")
	}
	c.mu.Lock()
	c.saved = snapshot.Sessions
	c.state.Accounts = nil
	for _, s := range snapshot.Sessions {
		c.state.Accounts = append(c.state.Accounts, s.Username)
	}
	c.mu.Unlock()
	return nil
}
func (c *Controller) restore() {
	ctx, ok := c.begin(false, "signin", "")
	if !ok {
		return
	}
	c.mu.Lock()
	c.state.Operation = "signin"
	c.state.AccountMessage = "Checking saved accounts…"
	c.mu.Unlock()
	c.publish()
	err := c.readSaved()
	if err == nil && c.services.Accounts != nil {
		snapshot, loadErr := c.services.Accounts.Load()
		err = loadErr
		if err == nil {
			for _, s := range snapshot.Sessions {
				if accounts.Key(s.Username) == accounts.Key(snapshot.Active) {
					err = c.validate(ctx, s)
					break
				}
			}
		}
	}
	c.mu.Lock()
	if err == nil {
		c.state.AccountMessage = ""
	}
	c.mu.Unlock()
	c.end(ctx, err)
}
func (c *Controller) validate(ctx context.Context, s *apple.Session) error {
	teams, err := c.services.Teams(ctx, s)
	if err != nil {
		c.mu.Lock()
		c.state.SignInUsername = s.Username
		hasCurrent := c.session != nil && c.state.Authenticated
		c.mu.Unlock()
		if hasCurrent {
			return fmt.Errorf("Couldn’t switch accounts. Your current account is still signed in. %w", err)
		}
		return fmt.Errorf("Sign in again to continue. %w", err)
	}
	if len(teams) == 0 {
		return errors.New("This account has no developer team. Check your Apple developer account.")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = s
	c.certificates = nil
	c.state.Certificates = nil
	c.state.Username = s.Username
	c.state.SignInUsername = ""
	c.state.Authenticated = true
	c.state.Teams = teams
	c.state.TeamID = teams[0].ID
	c.updateQuotaLocked()
	return nil
}
func (c *Controller) updateQuotaLocked() {
	c.state.Quota = "App ID allowance unavailable"
	for _, t := range c.state.Teams {
		if t.ID == c.state.TeamID {
			if t.AppIDsUnlimited {
				c.state.Quota = "Unlimited App IDs"
			} else if t.AvailabilityKnown {
				c.state.Quota = fmt.Sprintf("%d App IDs available", t.AppIDsAvailable)
			} else if t.LimitKnown {
				c.state.Quota = fmt.Sprintf("Up to %d App IDs every 7 days", t.AppIDLimit)
			}
		}
	}
}
func (c *Controller) login(username, password string) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return
	}
	ctx, ok := c.begin(false, "signin", "")
	if !ok {
		return
	}
	c.mu.Lock()
	c.state.Operation = "signin"
	c.state.SignInUsername = username
	c.state.AccountMessage = "Signing in to Apple…"
	c.mu.Unlock()
	c.publish()
	s, err := c.services.Login(ctx, username, password, func(ch apple.Challenge) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return c.services.Ask(ch)
	})
	password = ""
	if err == nil {
		err = c.validate(ctx, s)
	}
	if err == nil {
		c.mu.Lock()
		c.state.AccountMessage = ""
		c.mu.Unlock()
	}
	if err == nil && c.services.Accounts != nil {
		if saveErr := c.services.Accounts.Save(s); saveErr != nil {
			c.mu.Lock()
			c.state.AccountMessage = "Signed in for this run. Your account could not be saved securely."
			c.mu.Unlock()
		} else {
			_ = c.readSaved()
			c.mu.Lock()
			c.state.AccountMessage = ""
			c.mu.Unlock()
		}
	}
	c.end(ctx, err)
}
func (c *Controller) resume(username string) {
	ctx, ok := c.begin(false, "signin", "")
	if !ok {
		return
	}
	c.mu.Lock()
	c.state.Operation = "signin"
	c.state.AccountMessage = "Checking saved sign-in…"
	c.state.Certificates = nil
	c.certificates = nil
	var selected *apple.Session
	for _, s := range c.saved {
		if accounts.Key(s.Username) == accounts.Key(username) {
			selected = s
		}
	}
	c.mu.Unlock()
	c.publish()
	var err error
	if selected == nil {
		err = errors.New("This saved account is unavailable. Sign in again.")
	} else {
		err = c.validate(ctx, selected)
	}
	if err == nil {
		if c.services.Accounts != nil {
			err = c.services.Accounts.Select(selected.Username)
		}
		c.mu.Lock()
		c.state.AccountMessage = ""
		c.mu.Unlock()
	}
	c.end(ctx, err)
}
func (c *Controller) clearAccountLocked() {
	c.session = nil
	c.certificates = nil
	c.state.Authenticated = false
	c.state.Username = ""
	c.state.Teams = nil
	c.state.TeamID = ""
	c.state.Quota = ""
	c.state.Certificates = nil
	c.state.SignInUsername = ""
	c.state.AccountMessage = ""
}
func (c *Controller) signOut() {
	ctx, ok := c.begin(false, "account", "")
	if !ok {
		return
	}
	var err error
	if c.services.Accounts != nil {
		err = c.services.Accounts.Deactivate()
	}
	if err == nil {
		c.mu.Lock()
		c.clearAccountLocked()
		c.mu.Unlock()
	}
	c.end(ctx, err)
}
func (c *Controller) forget(username string) {
	ctx, ok := c.begin(false, "account", "")
	if !ok {
		return
	}
	c.mu.Lock()
	c.state.Operation = "account"
	c.mu.Unlock()
	var err error
	if c.services.Accounts != nil {
		err = c.services.Accounts.Remove(username)
		if err == nil {
			c.mu.Lock()
			if c.session != nil && accounts.Key(c.session.Username) == accounts.Key(username) {
				c.clearAccountLocked()
			}
			c.mu.Unlock()
			err = c.readSaved()
		}
	}
	c.end(ctx, err)
}
func (c *Controller) selectTeam(id string) {
	c.mu.Lock()
	if c.state.Busy || c.session == nil {
		c.mu.Unlock()
		return
	}
	for _, t := range c.state.Teams {
		if t.ID == id {
			c.state.TeamID = id
			c.state.Certificates = nil
			c.certificates = nil
			c.updateQuotaLocked()
			break
		}
	}
	c.mu.Unlock()
	c.publish()
}
func (c *Controller) credentials() (*apple.Session, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session, c.state.TeamID
}
func (c *Controller) operate(id string) {
	kind := "refresh"
	if id == "" {
		kind = "install"
	}
	ctx, ok := c.begin(true, kind, id)
	if !ok {
		return
	}
	session, team := c.credentials()
	if id != "" && c.services.RefreshTeam != nil {
		if original := c.services.RefreshTeam(id); original != "" && original != team {
			// Prefer the app's original team automatically when this account owns it.
			c.mu.Lock()
			found := false
			for _, t := range c.state.Teams {
				if t.ID == original {
					team = original
					found = true
					break
				}
			}
			c.mu.Unlock()
			if !found {
				c.end(ctx, errors.New("Sign in with the Apple Account used to install this app."))
				return
			}
		}
	}
	var result platform.Result
	var err error
	path := ""
	retain := false
	if id == "" {
		path, retain, err = c.importIPA(ctx, "", team)
	}
	if err == nil && (id != "" || path != "") {
		c.progress(platform.Progress{Message: "Connecting to this iPhone…"})
		var device platform.Device
		device, err = c.services.Device(ctx)
		if err == nil {
			if id != "" {
				result, err = c.services.Refresh(ctx, session, team, id, device, c.progress)
			} else {
				result, err = c.services.Install(platform.WithIOSPackageRetention(ctx, retain), session, team, path, device, c.progress)
			}
			if errors.Is(err, platform.ErrRefreshNeedsIPA) && ctx.Err() == nil && c.services.ConfirmFallback != nil && c.services.ConfirmFallback(id) {
				path, retain, err = c.importIPA(ctx, id, team)
				if err == nil && path != "" {
					result, err = c.services.Install(platform.WithIOSPackageRetention(ctx, retain), session, team, path, device, c.progress)
				} else if err == nil {
					err = context.Canceled
				}
			}
		}
	}
	if path != "" {
		_ = os.Remove(path)
		_ = os.Remove(filepath.Dir(path))
	}
	if err == nil {
		message := result.CompletionMessage
		if message == "" {
			if id == "" && path == "" {
				message = "Import cancelled."
			} else if result.Installed {
				message = "App installed."
			} else {
				message = "Refresh complete."
			}
		}
		c.progress(platform.Progress{Fraction: 1, Message: message})
	}
	c.end(ctx, err)
	if c.services.Reload != nil {
		c.services.Reload()
	}
}
func (c *Controller) importIPA(ctx context.Context, expected, team string) (string, bool, error) {
	path, err := c.services.ChooseIPA()
	if err != nil {
		return path, false, err
	}
	if path == "" {
		return "", false, context.Canceled
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
			_ = os.Remove(filepath.Dir(path))
		}
	}()
	if err = ctx.Err(); err != nil {
		return "", false, err
	}
	info, err := ipa.Inspect(path)
	if err != nil {
		return "", false, err
	}
	// Installed paid/free bundle IDs can differ from the original IPA's ID.
	if expected != "" && expected != info.BundleID && expected != info.BundleID+"."+team {
		return "", false, errors.New("Choose the original IPA for this app.")
	}
	confirmed, retain, err := c.services.ConfirmIPA(info)
	if err != nil {
		return "", false, err
	}
	if !confirmed {
		return "", false, context.Canceled
	}
	if err = ctx.Err(); err != nil {
		return "", false, err
	}
	keep = true
	return path, retain, nil
}
func (c *Controller) connection() {
	ctx, ok := c.begin(false, "account", "")
	if !ok {
		return
	}
	c.mu.Lock()
	c.state.Operation = "account"
	c.mu.Unlock()
	err := c.services.Connection()
	c.end(ctx, err)
	if c.services.Reload != nil {
		c.services.Reload()
	}
}
func (c *Controller) manageCertificates(hash string) {
	ctx, ok := c.begin(true, "account", "")
	if !ok {
		return
	}
	c.mu.Lock()
	c.state.Operation = "account"
	c.mu.Unlock()
	session, team := c.credentials()
	var err error
	if hash != "" {
		c.mu.Lock()
		var cert *apple.DevelopmentCertificate
		for _, v := range c.certificates {
			if v.SHA256 == hash {
				copy := v
				cert = &copy
				break
			}
		}
		c.mu.Unlock()
		if cert == nil {
			err = errors.New("Reload certificates before revoking a certificate.")
		} else {
			err = c.services.Revoke(ctx, session, team, *cert)
		}
	}
	if err == nil {
		var certs []apple.DevelopmentCertificate
		certs, err = c.services.Certificates(ctx, session, team)
		if err == nil {
			c.mu.Lock()
			sort.SliceStable(certs, func(i, j int) bool { return certs[i].IssuedAt.After(certs[j].IssuedAt) })
			c.certificates = certs
			c.state.Certificates = certs
			c.state.AccountMessage = ""
			c.mu.Unlock()
		}
	}
	c.end(ctx, err)
}

// Device lookups are bounded independently of longer signing operations.
const deviceTimeout = 30 * time.Second

// UpdateApps keeps batch eligibility tied to recorded account attribution, never
// inferred from a shared developer team. Unknown accounts require individual refresh.
func (c *Controller) UpdateApps(apps []platform.IOSApp) {
	c.mu.Lock()
	c.apps = append([]platform.IOSApp(nil), apps...)
	c.mu.Unlock()
	c.publish()
}
func (c *Controller) eligibleLocked() []platform.IOSApp {
	var apps []platform.IOSApp
	if c.session == nil {
		return apps
	}
	for _, app := range c.apps {
		if !app.CanRefresh || accounts.Key(app.Account) != accounts.Key(c.session.Username) {
			continue
		}
		for _, team := range c.state.Teams {
			if team.ID == app.Team {
				apps = append(apps, app)
				break
			}
		}
	}
	sort.SliceStable(apps, func(i, j int) bool {
		if apps[i].Self != apps[j].Self {
			return !apps[i].Self
		}
		return apps[i].Name < apps[j].Name
	})
	return apps
}
func (c *Controller) updateVPN() {
	if c.services.VPNState == nil {
		return
	}
	available, connected := c.services.VPNState()
	c.mu.Lock()
	changed := c.state.VPNAvailable != available || c.state.VPNConnected != connected
	c.state.VPNAvailable, c.state.VPNConnected = available, connected
	c.mu.Unlock()
	if changed {
		c.publish()
	}
}
func (c *Controller) setVPN(on bool) {
	c.mu.Lock()
	if c.state.Busy || c.state.VPNBusy || c.services.SetVPN == nil {
		c.mu.Unlock()
		return
	}
	c.state.VPNBusy = true
	c.state.VPNRequested = on
	c.state.VPNMessage = ""
	c.mu.Unlock()
	c.publish()
	err := c.services.SetVPN(on)
	c.updateVPN()
	c.mu.Lock()
	c.state.VPNBusy = false
	if err != nil {
		c.state.VPNMessage = err.Error()
	}
	c.mu.Unlock()
	c.publish()
	if c.services.Reload != nil {
		c.services.Reload()
	}
}
func (c *Controller) refreshAll() {
	ctx, ok := c.begin(true, "refreshall", "")
	if !ok {
		return
	}
	c.mu.Lock()
	apps := c.eligibleLocked()
	c.mu.Unlock()
	session, _ := c.credentials()
	if len(apps) == 0 {
		c.end(ctx, errors.New("No apps match this Apple Account. Refresh an app individually to verify its account."))
		return
	}
	device, err := c.services.Device(ctx)
	if err != nil {
		c.end(ctx, err)
		return
	}
	completed, failed := 0, 0
	var fatal error
	for i, app := range apps {
		if ctx.Err() != nil {
			fatal = ctx.Err()
			break
		}
		c.mu.Lock()
		c.state.Target = app.BundleID
		c.mu.Unlock()
		label := fmt.Sprintf("%d of %d · %s", i+1, len(apps), app.Name)
		report := func(p platform.Progress) {
			p.Message = label + "\n" + p.Message
			p.Fraction = (float64(i) + p.Fraction) / float64(len(apps))
			c.progress(p)
		}
		report(platform.Progress{Message: "Checking signing profile…"})
		result, refreshErr := c.services.Refresh(ctx, session, app.Team, app.BundleID, device, report)
		outcome := result.CompletionMessage
		if outcome == "" {
			outcome = "Refresh complete."
		}
		if refreshErr != nil {
			outcome = refreshErr.Error()
		}
		c.mu.Lock()
		c.state.Results = append(c.state.Results, app.Name+": "+outcome)
		c.mu.Unlock()
		if refreshErr != nil {
			failed++
			report(platform.Progress{Message: refreshErr.Error()})
			var portal *apple.Error
			if ctx.Err() != nil || (errors.As(refreshErr, &portal) && portal.Code == 1100) {
				fatal = refreshErr
				break
			}
		} else {
			completed++
			report(platform.Progress{Fraction: 1, Message: result.CompletionMessage})
		}
	}
	if fatal == nil {
		if failed > 0 {
			fatal = fmt.Errorf("%d checked; %d need attention. Open Show Details for results, then refresh those apps individually.", completed, failed)
		} else {
			c.progress(platform.Progress{Fraction: 1, Message: "All apps are up to date."})
		}
	}
	c.end(ctx, fatal)
	if c.services.Reload != nil {
		c.services.Reload()
	}
}
