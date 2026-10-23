//go:build !ios

// Package ui contains the guided desktop screen. Workers update Fyne only via Do.
package ui

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/authclient"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

var Brand = fyne.NewStaticResource("ipa-loader.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><rect x="0" y="0" width="128" height="128" rx="29" ry="29" fill="#087f8c"/><rect x="38" y="18" width="52" height="92" rx="12" ry="12" fill="none" stroke="white" stroke-width="7"/><path d="M64 40v37m-14-14 14 14 14-14" fill="none" stroke="white" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/><path d="M58 96h12" stroke="white" stroke-width="5" stroke-linecap="round"/></svg>`))

// MacIcon centers an 824px continuous-corner tile on a transparent 1024px canvas for the Mac Dock.
// Coordinates are intrinsic so legacy SVG rasterizers preserve stroke widths.
var MacIcon = fyne.NewStaticResource("ipa-loader-macos.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024"><path d="M398 100h228c104 0 156 0 196 20 36 18 64 46 82 82 20 40 20 92 20 196v228c0 104 0 156-20 196-18 36-46 64-82 82-40 20-92 20-196 20H398c-104 0-156 0-196-20-36-18-64-46-82-82-20-40-20-92-20-196V398c0-104 0-156 20-196 18-36 46-64 82-82 40-20 92-20 196-20Z" fill="#087f8c"/><rect x="344.625" y="215.875" width="334.75" height="592.25" rx="77.25" ry="77.25" fill="none" stroke="white" stroke-width="45.0625"/><path d="M512 357.5v238.1875m-90.125-90.125 90.125 90.125 90.125-90.125" fill="none" stroke="white" stroke-width="45.0625" stroke-linecap="round" stroke-linejoin="round"/><path d="M473.375 718h77.25" stroke="white" stroke-width="32.1875" stroke-linecap="round"/></svg>`))

func ApplicationIcon() fyne.Resource {
	if runtime.GOOS == "darwin" {
		return macDockIcon()
	}
	return Brand
}

type Services struct {
	LoaderLabel                  string
	Bootstrap                    func(context.Context, *apple.Session, string, platform.Device, func(platform.Progress)) (platform.Result, error)
	ChooseIPA                    func(string) (string, error)
	DevelopmentCertificates      func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error)
	RevokeDevelopmentCertificate func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error
	Accounts                     *accounts.Store
	Login                        func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error)
	Teams                        func(context.Context, *apple.Session) ([]apple.Team, error)
	Devices                      func(context.Context) ([]platform.Device, error)
	Sideload                     func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error)
	ExtensionSelection           func(string, string, string) (*ipa.ExtensionSelection, error)
}

func NativeServices() Services {
	client := authclient.New()
	services := Services{LoaderLabel: loaderActionLabel, Bootstrap: func(ctx context.Context, s *apple.Session, t string, d platform.Device, p func(platform.Progress)) (platform.Result, error) {
		return platform.BootstrapLoader(ctx, client, s, t, d, p)
	}, DevelopmentCertificates: client.DevelopmentCertificates, RevokeDevelopmentCertificate: client.RevokeDevelopmentCertificate, Accounts: accounts.Native(), Login: client.Login, Teams: client.TeamsWithAllowance, Devices: platform.Devices,
		Sideload: func(ctx context.Context, s *apple.Session, t, p string, d platform.Device, progress func(platform.Progress)) (platform.Result, error) {
			return platform.Sideload(ctx, client, s, t, p, d, progress)
		}}
	services.ExtensionSelection = platform.LoadExtensionSelection
	return services
}

type Screen struct {
	Window              fyne.Window
	services            Services
	session             *apple.Session
	teams               []apple.Team
	devices             []platform.Device
	selected            *ipa.Info
	extensionOptions    *fyne.Container
	extensionChecks     []*widget.Check
	extensionCost       *widget.Label
	extensionChoiceErr  error
	extensionDialog     dialog.Dialog
	busy, discovering   bool
	allowanceGeneration uint64
	certificateRecovery *certificateRecovery
	loader              *widget.Button
	manageCertificates  *widget.Button
	cancel              context.CancelFunc

	accountButton                  *widget.Button
	accountDialog                  *dialog.CustomDialog
	loginFields                    *fyne.Container
	loginNeedsPassword             bool
	taskTabs                       *container.AppTabs
	setupTask                      *container.TabItem
	installing                     bool
	operationDialog                *widget.PopUp
	operationHeading               *widget.Label
	operationContent               *fyne.Container
	operationSetup                 bool
	operationAccount               *widget.Button
	switchAccountButton            *widget.Button
	accountsDialog                 *dialog.CustomDialog
	accountRemoveButtons           []*widget.Button
	operationMessage               *container.Scroll
	operationStatus                *widget.Label
	operationDone, reviewOperation *widget.Button

	root                                                        *fyne.Container
	loginPage                                                   *container.Scroll
	installPage                                                 *fyne.Container
	installBody                                                 *container.Scroll
	username, password                                          *widget.Entry
	signIn, choose, refresh, install, cancelButton, loginCancel *widget.Button
	team, device                                                *widget.Select
	accountStatus, appName, appDetail, status, deviceHint       *widget.Label
	accountName, accountQuota                                   *widget.Label
	showActivity                                                *widget.Button
	installAction                                               *fyne.Container
	appPanel                                                    fyne.CanvasObject
	icon                                                        *canvas.Image
	progress                                                    *slimProgress
	activity                                                    *widget.Label
	activityScroll                                              *container.Scroll
	logs                                                        []string
	details                                                     *widget.Button
	diagnosticDirectory                                         string
	savedAccounts                                               []*apple.Session
	savedSelector                                               *widget.Select
	savedRow                                                    *fyne.Container
	forgetAccount                                               *widget.Button
	continueAccount                                             *widget.Button
	updatingAccounts, accountsLoaded                            bool
}

func New(window fyne.Window, services Services) *Screen {
	s := &Screen{Window: window, services: services}
	s.username = widget.NewEntry()
	s.username.SetPlaceHolder("Apple Account email")
	s.password = widget.NewPasswordEntry()
	s.password.SetPlaceHolder("Password")
	s.initAccounts()
	s.accountStatus = wrap("")
	s.accountStatus.Hide()
	s.signIn = widget.NewButton("Sign in", s.login)
	s.signIn.Importance = widget.HighImportance
	s.password.OnSubmitted = func(string) { s.login() }
	cancel := func() {
		if s.cancel != nil {
			s.cancel()
		}
	}
	s.loginCancel = widget.NewButton("Cancel", cancel)
	s.loginCancel.Hide()
	logo := canvas.NewImageFromResource(Brand)
	logo.SetMinSize(fyne.NewSize(52, 52))
	logo.FillMode = canvas.ImageFillContain
	title := widget.NewLabelWithStyle("IPA Loader", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	title.SizeName = theme.SizeNameHeadingText
	intro := caption(platformIntro)
	intro.Wrapping = fyne.TextWrapWord
	intro.Alignment = fyne.TextAlignCenter
	privacy := caption("Your password is never saved.")
	privacy.Alignment = fyne.TextAlignCenter
	fields := column(12,
		column(4, caption("Apple Account"), control(40, loginEntry(s.username))),
		column(4, caption("Password"), control(40, loginEntry(s.password))))

	s.loginFields = column(16, fields, control(40, s.signIn), privacy)
	loginContent := column(24, column(8, container.NewCenter(logo), title, intro),
		s.savedRow, s.loginFields, s.loginCancel, s.accountStatus)
	s.loginPage = container.NewVScroll(inset(32, container.New(readableWidth{440}, loginContent)))

	s.switchAccountButton = widget.NewButton("Switch Account…", s.showAccountMenu)
	s.accountName = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	singleLine(s.accountName)
	s.accountQuota = caption("")
	singleLine(s.accountQuota)
	s.team = widget.NewSelect(nil, func(string) { s.dismissCertificateRecovery(); s.updateQuota(); s.loadExtensionChoices(); s.readiness() })
	s.team.PlaceHolder = "Choose a developer team"
	s.team.Hide()
	s.icon = canvas.NewImageFromResource(placeholderIcon)
	s.icon.FillMode = canvas.ImageFillContain
	s.icon.SetMinSize(fyne.NewSize(48, 48))
	s.icon.CornerRadius = 11
	s.appName = widget.NewLabelWithStyle("Choose an IPA", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	s.appName.SizeName = theme.SizeNameSubHeadingText
	singleLine(s.appName)
	s.appDetail = caption("Or drop an IPA file into this window.")
	singleLine(s.appDetail)
	s.choose = widget.NewButton("Choose IPA…", s.chooseIPA)
	s.device = widget.NewSelect(nil, func(string) { s.updateDeviceHint(); s.readiness(); s.showReadyStatus() })
	s.device.PlaceHolder = "Select your iPhone"
	s.refresh = widget.NewButtonWithIcon("Rescan", theme.ViewRefreshIcon(), s.refreshDevices)
	s.deviceHint = caption("Connect your iPhone, unlock it, and tap Trust if asked.")
	s.deviceHint.Wrapping = fyne.TextWrapWord
	s.install = widget.NewButton("Install App", s.sideload)
	s.install.Importance = widget.HighImportance
	label := services.LoaderLabel
	if label == "" {
		label = "Set Up IPA Loader"
	}
	s.loader = widget.NewButton(label, func() { s.runInstall(true) })
	if services.Bootstrap == nil {
		s.loader.Hide()
	}
	s.loader.Importance = widget.HighImportance
	s.installAction = control(40, s.install)
	s.cancelButton = widget.NewButton("Cancel", cancel)
	s.cancelButton.Hide()
	s.details = widget.NewButton("Open diagnostics", func() {
		if s.diagnosticDirectory != "" {
			_ = fyne.CurrentApp().OpenURL(&url.URL{Scheme: "file", Path: s.diagnosticDirectory})
		}
	})
	s.details.Hide()
	s.manageCertificates = widget.NewButton("Development Certificates…", func() { s.hideAccountDialog(); s.manageDevelopmentCertificates() })
	s.manageCertificates.Importance = widget.LowImportance
	s.manageCertificates.Alignment = widget.ButtonAlignTrailing
	s.manageCertificates.Alignment = widget.ButtonAlignLeading
	s.manageCertificates.Hide()
	s.progress = newSlimProgress()
	s.progress.Hide()
	s.status = wrap("")
	s.status.Importance = widget.LowImportance
	s.activity = wrap("")
	s.activity.TextStyle.Monospace = true
	s.activity.SizeName = theme.SizeNameCaptionText
	s.activityScroll = container.NewVScroll(s.activity)
	s.activityScroll.SetMinSize(fyne.NewSize(100, 110))
	s.activityScroll.Hide()
	s.showActivity = widget.NewButtonWithIcon("Show details", theme.MenuDropDownIcon(), s.toggleActivity)
	s.showActivity.Importance = widget.LowImportance
	s.showActivity.Hide()
	s.accountButton = widget.NewButtonWithIcon("Account…", theme.AccountIcon(), s.showAccountDialog)
	headerLogo := canvas.NewImageFromResource(ApplicationIcon())
	headerLogo.SetMinSize(fyne.NewSize(40, 40))
	headerLogo.FillMode = canvas.ImageFillContain
	heading := widget.NewLabelWithStyle("IPA Loader", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	heading.SizeName = theme.SizeNameSubHeadingText
	header := container.NewBorder(nil, nil, nil, control(36, s.accountButton), container.NewHBox(headerLogo, heading))
	appRow := appPickerLayout(s.icon, s.appName, s.appDetail, s.choose)
	s.extensionOptions = container.NewVBox()
	s.extensionOptions.Hide()
	s.appPanel = surface(appRow)
	installTask := container.NewTabItem("Install an IPA", s.appPanel)
	setupIcon := canvas.NewImageFromResource(Brand)
	setupIcon.SetMinSize(fyne.NewSize(48, 48))
	setupIcon.FillMode = canvas.ImageFillContain
	setupTitle := widget.NewLabelWithStyle("IPA Loader for iPhone", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	setupTitle.Truncation = fyne.TextTruncateEllipsis
	setupDetail := caption("Install and refresh apps from your iPhone.\nThe app is included. No IPA file needed.")
	setupDetail.Wrapping = fyne.TextWrapWord
	s.setupTask = container.NewTabItem("Set Up IPA Loader", surface(container.NewBorder(nil, nil, container.NewCenter(setupIcon), nil, column(4, setupTitle, setupDetail))))
	s.taskTabs = container.NewAppTabs(installTask)
	if services.Bootstrap != nil {
		s.taskTabs.Append(s.setupTask)
	}
	s.taskTabs.OnSelected = func(item *container.TabItem) {
		action := s.install
		if item == s.setupTask {
			action = s.loader
		}
		s.installAction.Objects = []fyne.CanvasObject{action}
		s.installAction.Refresh()
		s.readiness()
		s.showReadyStatus()
	}
	deviceSection := surface(column(8, container.NewBorder(nil, nil, nil, control(40, s.refresh), control(40, s.device)), s.deviceHint))
	s.reviewOperation = widget.NewButton("View Last Installation…", func() { s.showOperation("Installation") })
	s.reviewOperation.Importance = widget.LowImportance
	s.reviewOperation.Hide()
	installContent := column(16, header, deviceSection, s.taskTabs,
		column(8, s.installAction, s.status, s.reviewOperation))
	body := container.New(insetLayout{16, 24, 20, 24}, installContent)
	s.installBody = container.NewVScroll(body)
	s.installPage = container.NewStack(s.installBody)
	s.installPage.Hide()
	s.root = container.NewStack(s.loginPage, s.installPage)
	window.SetContent(s.root)
	window.Resize(fyne.NewSize(600, 560))
	window.SetMaster()
	window.SetIcon(ApplicationIcon())
	window.SetOnDropped(func(_ fyne.Position, uris []fyne.URI) {
		if !s.busy && s.session != nil && len(uris) > 0 {
			s.loadIPA(uris[0].Path())
		}
	})
	window.SetOnClosed(s.dismissCertificateRecovery)
	window.SetCloseIntercept(func() { s.dismissCertificateRecovery(); cancel(); window.SetCloseIntercept(nil); window.Close() })
	s.readiness()
	return s
}

func (s *Screen) returnToLogin() {
	s.hideAccountDialog()
	s.hideAccountsDialog()
	if s.busy {
		return
	}
	s.dismissCertificateRecovery()
	s.session = nil
	s.teams = nil
	s.password.SetText("")
	s.accountStatus.SetText("")
	s.accountStatus.Hide()
	s.logs = nil
	s.activity.SetText("")
	s.activityScroll.Hide()
	s.showActivity.Hide()
	s.details.Hide()
	s.diagnosticDirectory = ""
	s.progress.Hide()
	s.reviewOperation.Hide()
	if s.operationDialog != nil {
		s.operationDialog.Hide()
		s.operationDialog = nil
	}
	s.status.Show()
	s.installPage.Hide()
	s.loginPage.Show()
	s.updateAccountContinuation()
	if s.continueAccount.Visible() && !s.continueAccount.Disabled() {
		s.Window.Canvas().Focus(s.continueAccount)
	} else {
		s.Window.Canvas().Focus(s.username)
	}
	s.readiness()
}

func (s *Screen) showAccount(session *apple.Session, teams []apple.Team) {
	s.dismissCertificateRecovery()
	s.allowanceGeneration++
	s.session = session
	s.username.SetText(session.Username)
	s.teams = teams
	s.loginNeedsPassword = false
	options := make([]string, len(teams))
	for i, t := range teams {
		options[i] = t.Name
		if options[i] == "" {
			options[i] = "Developer team"
		}
		if len(teams) > 1 {
			options[i] += fmt.Sprintf(" (%d)", i+1)
		}
	}
	s.team.Options = options
	s.team.ClearSelected()
	if len(teams) == 1 {
		s.team.SetSelectedIndex(0)
		s.team.Hide()
	} else {
		s.team.Show()
	}
	s.team.Refresh()
	s.updateQuota()
	s.loginPage.Hide()
	s.installPage.Show()
	s.Window.Canvas().Unfocus()
	s.readiness()
}

func wrap(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Wrapping = fyne.TextWrapWord
	return l
}

func (s *Screen) Start() {
	if !s.accountsLoaded && s.services.Accounts != nil {
		s.accountsLoaded = true
		s.loadAccounts()
		return
	}
	if s.session != nil && s.services.Devices != nil {
		s.refreshDevices()
	}
}

func (s *Screen) setBusy(b bool) {
	s.busy = b
	if b {
		s.status.Importance = widget.MediumImportance
	} else {
		s.status.Importance = widget.LowImportance
	}
	for _, entry := range []*widget.Entry{s.username, s.password} {
		if b {
			entry.Disable()
		} else {
			entry.Enable()
		}
	}
	for _, check := range s.extensionChecks {
		if b {
			check.Disable()
		} else {
			check.Enable()
		}
	}
	buttons := []*widget.Button{s.signIn, s.choose, s.refresh, s.forgetAccount, s.continueAccount, s.manageCertificates, s.accountButton, s.switchAccountButton}
	buttons = append(buttons, s.accountRemoveButtons...)
	for _, button := range buttons {
		if b {
			button.Disable()
		} else {
			button.Enable()
		}
	}
	for _, selectWidget := range []*widget.Select{s.team, s.device, s.savedSelector} {
		if b {
			selectWidget.Disable()
		} else {
			selectWidget.Enable()
		}
	}
	s.cancelButton.Hide()
	s.loginCancel.Hide()
	if b && s.cancel != nil {
		if s.session == nil {
			s.loginCancel.Show()
		} else {
			s.cancelButton.Show()
		}
	} else if !b && s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	s.readiness()
	if !b && (s.savedSelector.SelectedIndex() < 0 || s.savedSelector.SelectedIndex() >= len(s.savedAccounts)) {
		s.forgetAccount.Disable()
	}
	s.updateAccountContinuation()
}

func (s *Screen) readiness() {
	s.updateCertificateAction()
	if s.loader != nil {
		if !s.busy && s.session != nil && s.team.SelectedIndex() >= 0 && s.device.SelectedIndex() >= 0 && s.device.SelectedIndex() < len(s.devices) && s.services.Bootstrap != nil {
			s.loader.Enable()
		} else {
			s.loader.Disable()
		}
	}
	ready := !s.busy && s.session != nil && s.selected != nil && s.extensionChoiceErr == nil && s.team.SelectedIndex() >= 0 && s.device.SelectedIndex() >= 0 && s.device.SelectedIndex() < len(s.devices)
	if ready {
		s.install.Enable()
	} else {
		s.install.Disable()
	}
	if !s.busy && len(s.logs) == 0 {
		s.showReadyStatus()
	}
	s.root.Refresh()
}

func (s *Screen) showReadyStatus() {
	if s.busy {
		return
	}
	switch {
	case s.team.SelectedIndex() < 0:
		s.setStatus("Choose a developer team in Account to continue.")
	case s.device.SelectedIndex() < 0:
		s.setStatus("Connect and select your iPhone to continue.")
	case s.taskTabs.Selected() == s.setupTask:
		s.setStatus("Ready to set up IPA Loader on your iPhone.")
	case s.selected == nil:
		s.setStatus("Choose an IPA file to install.")
	case s.extensionChoiceErr != nil:
		s.setStatus(s.extensionChoiceErr.Error())
	default:
		s.setStatus("Ready to install on your iPhone.")
	}
}

func (s *Screen) login() {
	if s.busy || s.session != nil {
		return
	}
	username, password := strings.TrimSpace(s.username.Text), s.password.Text
	if username == "" || password == "" {
		s.accountStatus.SetText("Enter your Apple Account email and password.")
		s.accountStatus.Show()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.setBusy(true)
	s.signIn.SetText("Signing in…")
	s.accountStatus.SetText("Signing in to Apple…")
	s.accountStatus.Show()
	s.setStatus("Connecting to Apple…")
	go func() {
		session, err := s.services.Login(ctx, username, password, func(ch apple.Challenge) (string, error) { return s.challenge(ctx, ch) })
		password = ""
		var teams []apple.Team
		if err == nil {
			teams, err = s.services.Teams(ctx, session)
			if err == nil && len(teams) == 0 {
				err = errors.New("This account has no developer team. Complete enrollment in Apple's developer account settings.")
			}
		}
		var saveError error
		var saved accounts.Snapshot
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil && s.services.Accounts != nil {
			saveError = s.services.Accounts.Save(session)
			if saveError == nil {
				saved, saveError = s.services.Accounts.Load()
			}
		}
		fyne.Do(func() {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			s.password.SetText("")
			s.setBusy(false)
			s.signIn.SetText("Sign in")
			if err != nil {
				message := friendly(err)
				if errors.Is(err, context.Canceled) {
					message = "Sign-in cancelled."
				}
				s.accountStatus.SetText(message)
				s.accountStatus.Show()
				s.setStatus("Sign-in did not complete.")
				return
			}
			s.showAccount(session, teams)
			if saveError == nil && s.services.Accounts != nil {
				s.applySavedAccounts(saved)
			}
			if saveError != nil {
				s.applySavedAccounts(accounts.Snapshot{Sessions: s.savedAccounts})
				dialog.ShowInformation("Signed in for this run", "Your account is signed in, but could not be saved securely. You can continue using the app.\n\n"+saveError.Error(), s.Window)
			}
			s.Start()

		})
	}()
}

func (s *Screen) challenge(ctx context.Context, ch apple.Challenge) (string, error) {
	type answer struct {
		value string
		ok    bool
	}
	answers := make(chan answer, 1)
	var prompt dialog.Dialog
	fyne.Do(func() {
		if ctx.Err() != nil {
			return
		}
		if ch.Kind == "phone" {
			options := make([]string, len(ch.Phones))
			for i, p := range ch.Phones {
				options[i] = fmt.Sprintf("%d. %s", i+1, p.Label)
			}
			selectPhone := widget.NewSelect(options, nil)
			if len(options) > 0 {
				selectPhone.SetSelectedIndex(0)
			}
			prompt = dialog.NewCustomConfirm("Choose a trusted phone", "Send code", "Cancel", container.NewVBox(wrap(ch.Message), selectPhone), func(ok bool) {
				index := selectPhone.SelectedIndex()
				if !ok || index < 0 {
					answers <- answer{}
					return
				}
				answers <- answer{strconv.Itoa(ch.Phones[index].ID), true}
			}, s.Window)
		} else {
			code := widget.NewEntry()
			code.SetPlaceHolder("Six-digit verification code")
			code.Validator = func(value string) error {
				if len(value) != 6 {
					return errors.New("Enter six digits")
				}
				for _, r := range value {
					if r < '0' || r > '9' {
						return errors.New("Enter six digits")
					}
				}
				return nil
			}
			verification := dialog.NewForm("Verify your Apple Account", "Continue", "Cancel", []*widget.FormItem{
				widget.NewFormItem("", wrap(ch.Message)),
				widget.NewFormItem("Code", code),
			}, func(ok bool) { value := strings.TrimSpace(code.Text); code.SetText(""); answers <- answer{value, ok} }, s.Window)
			code.OnSubmitted = func(string) { verification.Submit() }
			prompt = verification
			prompt.Show()
			s.Window.Canvas().Focus(code)
			return
		}
		prompt.Show()
	})
	select {
	case result := <-answers:
		if !result.ok {
			return "", context.Canceled
		}
		return result.value, nil
	case <-ctx.Done():
		fyne.Do(func() {
			if prompt != nil {
				prompt.Hide()
			}
		})
		return "", ctx.Err()
	}
}

func (s *Screen) updateQuota() {
	allowance := "Choose a developer team"
	index := s.team.SelectedIndex()
	if index >= 0 && index < len(s.teams) {
		team := s.teams[index]
		switch {
		case team.AvailabilityKnown && team.LimitKnown && team.AppIDLimit > 0:
			allowance = fmt.Sprintf("%d of %d App IDs available", team.AppIDsAvailable, team.AppIDLimit)
		case team.LimitKnown && team.AppIDsUnlimited:
			allowance = "Unlimited App IDs"
		case team.LimitKnown && team.AppIDLimit > 0:
			allowance = fmt.Sprintf("Up to %d App IDs every 7 days", team.AppIDLimit)
		default:
			allowance = "App ID limit not provided by Apple"
		}
	}
	account := s.username.Text
	if s.session != nil && s.session.Username != "" {
		account = s.session.Username
	}
	s.accountName.SetText(account)
	s.accountQuota.SetText(allowance)
	s.accountName.Show()

}

func (s *Screen) updateDeviceHint() {
	i := s.device.SelectedIndex()
	if i < 0 || i >= len(s.devices) {
		return
	}
	d := s.devices[i]
	details := []string{}
	if d.Model != "" {
		details = append(details, d.Model)
	}
	if d.OSVersion != "" {
		details = append(details, "iOS "+d.OSVersion)
	}
	if len(details) > 0 {
		s.deviceHint.SetText(strings.Join(details, " · "))
	} else {
		s.deviceHint.SetText("Keep your iPhone connected and unlocked.")
	}
}

func (s *Screen) refreshDevices() {
	if s.session == nil || s.busy || s.discovering || s.services.Devices == nil {
		return
	}
	s.discovering = true
	s.refresh.Disable()
	s.deviceHint.SetText("Looking for connected iPhones…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), deviceTimeout)
		defer cancel()
		devices, err := s.services.Devices(ctx)
		fyne.Do(func() {
			s.discovering = false
			if !s.busy {
				s.refresh.Enable()
			}
			old := s.device.Selected
			oldID := ""
			oldTransport := ""
			if index := s.device.SelectedIndex(); index >= 0 && index < len(s.devices) {
				oldID = s.devices[index].ID
				oldTransport = s.devices[index].Transport
			}
			s.devices = devices
			options := make([]string, len(devices))
			for i, d := range devices {
				options[i] = desktopDeviceLabel(d)
				if options[i] == "" {
					options[i] = "iPhone"
				}
				for j := 0; j < i; j++ {
					if options[j] == options[i] {
						options[i] += fmt.Sprintf(" (%d)", i+1)
						break
					}
				}
			}
			s.device.Options = options
			s.device.ClearSelected()
			for i, name := range options {
				if (oldID != "" && devices[i].ID == oldID && devices[i].Transport == oldTransport) || (oldID == "" && name == old) {
					s.device.SetSelectedIndex(i)
					break
				}
			}
			if s.device.SelectedIndex() < 0 && oldID != "" {
				for i, device := range devices {
					if device.ID == oldID {
						s.device.SetSelectedIndex(i)
						break
					}
				}
			}

			if len(options) == 1 {
				s.device.SetSelectedIndex(0)
			}
			s.device.Refresh()
			if err != nil {
				s.deviceHint.SetText(friendly(err))
			} else if len(devices) == 0 {
				s.deviceHint.SetText(platformNoDevice)
			} else {
				s.updateDeviceHint()
			}
			s.readiness()
		})
	}()
}

func (s *Screen) chooseIPA() {
	if s.busy || s.session == nil {
		return
	}
	choose := s.services.ChooseIPA
	if choose == nil {
		choose = func(current string) (string, error) { return nativeIPAFile(s.Window, current) }
	}
	current := ""
	if s.selected != nil {
		current = s.selected.Path
	}
	s.setBusy(true)
	go func() {
		path, err := choose(current)
		fyne.Do(func() {
			s.setBusy(false)
			if err != nil {
				dialog.ShowError(err, s.Window)
				return
			}
			if path != "" {
				s.loadIPA(path)
			}
		})
	}()
}

func (s *Screen) loadIPA(path string) {
	if s.busy || s.session == nil {
		return
	}
	if !strings.EqualFold(filepath.Ext(path), ".ipa") {
		dialog.ShowError(errors.New("Choose a file ending in .ipa"), s.Window)
		return
	}
	s.setBusy(true)
	s.setStatus("Reading app information…")
	go func() {
		info, err := ipa.Inspect(path)
		fyne.Do(func() {
			s.setBusy(false)
			if err != nil {
				s.setStatus("That IPA could not be selected.")
				dialog.ShowError(err, s.Window)
				return
			}
			s.showIPA(info)
		})
	}()
}

func (s *Screen) showIPA(info *ipa.Info) {
	s.selected = info
	s.loadExtensionChoices()
	s.taskTabs.SelectIndex(0)
	s.choose.SetText("Change IPA…")
	s.appName.SetText(info.Name)
	s.updateSelectedAppDetail()
	if len(info.Icon) > 0 {
		s.icon.Resource = fyne.NewStaticResource("selected-app.png", info.Icon)
	} else {
		s.icon.Resource = placeholderIcon
	}
	s.icon.File = ""
	s.icon.Image = nil
	s.icon.Refresh()
	s.logs = nil
	s.activity.SetText("")
	s.collapseActivity()
	s.showActivity.Hide()
	s.details.Hide()
	s.diagnosticDirectory = ""
	s.progress.Hide()
	s.reviewOperation.Hide()
	s.readiness()
}

func (s *Screen) sideload() {
	if s.busy || s.selected == nil || s.extensionChoiceErr != nil {
		return
	}
	if len(s.selected.Extensions) == 0 {
		s.runInstall(false)
		return
	}
	if s.extensionDialog != nil {
		s.extensionDialog.Show()
		return
	}
	choices := container.NewVScroll(s.extensionOptions)
	choices.SetMinSize(fyne.NewSize(400, 180))
	name := wrap(s.selected.Name)
	name.TextStyle.Bold = true
	singleLine(name)
	content := column(12, name, s.extensionCost, choices,
		wrap("One App ID for the app, plus one per extension. Existing IDs are reused."),
		wrap("Turn off features you don't need. Your choices are remembered for refreshes."))
	s.extensionDialog = dialog.NewCustomConfirm("Install App", "Install", "Cancel", content, func(confirmed bool) {
		s.extensionDialog = nil
		if confirmed {
			s.runInstall(false)
		}
	}, s.Window)
	current := s.extensionDialog
	current.SetOnClosed(func() {
		if s.extensionDialog == current {
			s.extensionDialog = nil
		}
	})
	s.extensionDialog.Show()
}
func (s *Screen) runInstall(loader bool) {
	if s.busy || s.session == nil || (!loader && (s.selected == nil || s.extensionChoiceErr != nil)) || (loader && s.services.Bootstrap == nil) {
		return
	}
	teamIndex, deviceIndex := s.team.SelectedIndex(), s.device.SelectedIndex()
	if teamIndex < 0 || teamIndex >= len(s.teams) || deviceIndex < 0 || deviceIndex >= len(s.devices) {
		return
	}
	path := ""
	if !loader {
		path = s.selected.Path
	}
	session, team, device := s.session, s.teams[teamIndex].ID, s.devices[deviceIndex]
	s.dismissCertificateRecovery()
	if s.operationDialog != nil {
		s.operationDialog.Hide()
		s.operationDialog = nil
	}
	s.allowanceGeneration++
	ctx, cancel := context.WithCancel(context.Background())
	if !loader {
		ctx = platform.WithExtensionSelection(ctx, s.selected.SelectedExtensions())
	}
	s.cancel = cancel
	s.logs = nil
	s.details.Hide()
	s.diagnosticDirectory = ""
	s.activity.SetText("")
	s.collapseActivity()
	s.showActivity.Show()
	s.progress.SetValue(0)
	s.progress.Show()
	s.installing = true
	s.operationSetup = loader
	s.setBusy(true)
	operation := "Installing App…"
	if loader {
		operation = "Setting Up IPA Loader…"
	}
	s.setStatus("Preparing installation…")
	s.showOperation(operation)
	update := func(p platform.Progress) {
		fyne.Do(func() {
			s.progress.SetValue(p.Fraction)
			s.setStatus(p.Message)
			s.log(p.Message)
			s.root.Refresh()
		})
	}
	go func() {
		var result platform.Result
		var err error
		if loader {
			result, err = s.services.Bootstrap(ctx, session, team, device, update)
		} else {
			result, err = s.services.Sideload(ctx, session, team, path, device, update)
		}
		cancel()
		fyne.Do(func() {
			defer s.root.Refresh()
			s.setBusy(false)
			s.installAction.Show()
			defer s.finishOperation(err)
			s.refreshAllowance(session)
			if err != nil {
				s.status.Importance = widget.MediumImportance
				s.diagnosticDirectory = result.WorkDir
				if result.WorkDir != "" {
					s.details.Show()
				}
				s.setStatus(friendly(err))
				s.log(friendly(err))
				var portalError *apple.Error
				if errors.As(err, &portalError) && portalError.Code == 1100 {
					s.setStatus("Your Apple Account session has expired. Sign in again to continue.")
				}
				if errors.As(err, &portalError) && portalError.Code == 7460 {
					s.showCertificateQuota(session, team)
				}
				return
			}
			s.progress.SetValue(1)
			s.status.Importance = widget.MediumImportance
			message := "Installed on " + device.Name
			if result.Launched {
				message += " and ready to use"
			}
			if result.CompletionMessage != "" {
				message = result.CompletionMessage
			} else {
				message += "."
			}
			s.setStatus(message)
			s.log("Installation confirmed: version " + result.Version + ", build " + result.Build + ".")
		})
	}()
}

func (s *Screen) log(message string) {
	s.logs = append(s.logs, message)
	if len(s.logs) > 100 {
		s.logs = s.logs[len(s.logs)-100:]
	}
	s.activity.SetText(strings.Join(s.logs, "\n"))
	s.activityScroll.ScrollToBottom()
	if s.installing && s.activityScroll.Visible() {
		s.resizeOperation()
	}
}

func friendly(err error) string {
	if errors.Is(err, context.Canceled) {
		return "Cancelled. If installation had already started, check your iPhone before trying again."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "The operation timed out. Check your connection and try again."
	}
	return err.Error()
}
