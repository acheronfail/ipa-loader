//go:build !ios

package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/platform"
)

func desktopDeviceLabel(device platform.Device) string {
	name := device.Name
	if name == "" {
		name = "iPhone"
	}
	transport := device.Transport
	if strings.EqualFold(transport, "network") || strings.EqualFold(transport, "wifi") {
		transport = "Wi-Fi"
	}
	if transport != "" {
		return name + " · " + transport
	}
	return name
}

func (s *Screen) hideAccountDialog() {
	if s.accountDialog != nil {
		s.accountDialog.Hide()
		s.accountDialog = nil
	}
}

func (s *Screen) showAccountDialog() {
	if s.busy || s.session == nil {
		return
	}
	s.hideAccountDialog()
	teamName := "Choose a developer team"
	if i := s.team.SelectedIndex(); i >= 0 && i < len(s.teams) {
		teamName = s.teams[i].Name
		if teamName == "" {
			teamName = s.teams[i].ID
		}
	}
	teamLabel := widget.NewLabel(teamName)
	singleLine(teamLabel)
	team := fyne.CanvasObject(teamLabel)
	if len(s.teams) > 1 {
		team = control(40, s.team)
	}
	s.accountName.Show()
	content := column(16,
		column(4, caption("Apple Account"), s.accountName),
		column(4, caption("Developer Team"), team, s.accountQuota),
		control(40, s.manageCertificates), widget.NewSeparator(), control(40, s.switchAccountButton))
	s.accountDialog = dialog.NewCustom("Account", "Done", content, s.Window)
	current := s.accountDialog
	current.SetOnClosed(func() {
		if s.accountDialog == current {
			s.accountDialog = nil
		}
	})
	s.accountDialog.Resize(fyne.NewSize(fyne.Min(440, s.Window.Canvas().Size().Width-48), content.MinSize().Height+80))
	s.accountDialog.Show()
}

func (s *Screen) setStatus(message string) {
	s.status.SetText(message)
	if s.operationStatus != nil && s.installing {
		s.operationStatus.SetText(message)
	}
}

// The log fills the space between the summary and fixed action row.
func (s *Screen) showOperation(title string) {
	if s.operationDialog == nil {
		s.operationStatus = wrap(s.status.Text)
		s.operationMessage = container.NewVScroll(s.operationStatus)
		s.operationMessage.SetMinSize(fyne.NewSize(100, s.operationStatus.MinSize().Height))
		s.operationHeading = widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		s.operationHeading.SizeName = theme.SizeNameSubHeadingText
		singleLine(s.operationHeading)
		summary := ""
		if i := s.device.SelectedIndex(); i >= 0 && i < len(s.devices) {
			name := s.appName.Text
			if s.operationSetup {
				name = "IPA Loader"
			}
			summary = name + " · " + desktopDeviceLabel(s.devices[i])
		}
		destination := caption(summary)
		singleLine(destination)
		s.operationDone = widget.NewButton("Done", func() {
			s.operationDialog.Hide()
			s.status.Show()
		})
		s.operationDone.Importance = widget.HighImportance
		s.operationAccount = widget.NewButton("Sign In Again…", s.reauthenticate)
		s.operationAccount.Importance = widget.HighImportance
		s.operationAccount.Hide()
		if s.busy {
			s.operationDone.Hide()
		}
		top := column(8, s.operationHeading, destination, s.operationMessage, s.progress,
			container.NewBorder(nil, nil, control(36, s.showActivity), nil))
		actions := control(40, container.NewBorder(nil, nil, s.details,
			container.NewHBox(s.cancelButton, s.operationDone, s.operationAccount)))
		s.operationContent = inset(16, container.NewBorder(top, actions, nil, nil, s.activityScroll))
		s.operationDialog = widget.NewModalPopUp(s.operationContent, s.Window.Canvas())
	}
	s.status.Hide()
	s.operationDialog.Show()
	s.resizeOperation()
}

func (s *Screen) resizeOperation() {
	if s.operationDialog == nil {
		return
	}
	size := s.Window.Canvas().Size()
	width := fyne.Min(500, size.Width-40)
	// Bound long error messages without pushing the action row out of view.
	s.operationStatus.Resize(fyne.NewSize(width-32, s.operationStatus.MinSize().Height))
	s.operationMessage.SetMinSize(fyne.NewSize(100, fyne.Min(104, fyne.Max(24, s.operationStatus.MinSize().Height))))
	s.operationDialog.Resize(fyne.NewSize(width, s.operationDialog.MinSize().Height))
	if s.activityScroll.Visible() {
		base := s.operationDialog.MinSize().Height - s.activityScroll.MinSize().Height
		available := fyne.Max(48, size.Height-40-base)
		height := fyne.Min(180, fyne.Max(72, s.activity.MinSize().Height))
		s.activityScroll.SetMinSize(fyne.NewSize(100, fyne.Min(height, available)))
	}
	s.operationDialog.Resize(fyne.NewSize(width, s.operationDialog.MinSize().Height))
}

func (s *Screen) finishOperation(err error) {
	s.installing = false
	if s.operationDone != nil {
		s.operationDone.Show()
	}
	if s.operationHeading != nil {
		title := "Installed Successfully"
		if s.operationSetup {
			title = "iPhone Setup Complete"
		}
		s.operationHeading.Importance = widget.SuccessImportance
		if err != nil {
			s.operationDone.SetText("Close")
			title = "Installation Needs Attention"
			s.operationHeading.Importance = widget.DangerImportance
			if errors.Is(err, context.Canceled) {
				title = "Installation Stopped"
				s.operationHeading.Importance = widget.MediumImportance
			}
			var portal *apple.Error
			if errors.As(err, &portal) && portal.Code == 1100 {
				s.operationAccount.Show()
				s.operationDone.Importance = widget.LowImportance
				s.operationDone.Refresh()
			}
		}
		s.operationHeading.SetText(title)
	}
	s.progress.Hide()
	s.cancelButton.Hide()
	if len([]rune(s.status.Text)) > 200 {
		summary := "Installation complete. View the result for next steps."
		if err != nil {
			summary = "Installation needs attention. View the result for details."
		}
		s.status.SetText(summary)
	}
	s.reviewOperation.Show()
	s.resizeOperation()
}

func (s *Screen) reauthenticate() {
	if s.busy {
		return
	}
	if s.session != nil {
		s.username.SetText(s.session.Username)
	}
	s.returnToLogin()
	s.loginNeedsPassword = true
	s.updateAccountContinuation()
	s.Window.Canvas().Focus(s.password)
}

func (s *Screen) switchAccount(username string) {
	if s.busy {
		return
	}
	if username == "Add another account…" {
		s.returnToLogin()
		s.username.SetText("")
		s.updatingAccounts = true
		s.savedSelector.ClearSelected()
		s.updatingAccounts = false
		s.loginNeedsPassword = false
		s.forgetAccount.Disable()
		s.updateAccountContinuation()
		s.Window.Canvas().Focus(s.username)
		return
	}
	for _, session := range s.savedAccounts {
		if accounts.Key(session.Username) == accounts.Key(username) {
			s.resumeAccount(session)
			return
		}
	}
}

func (s *Screen) accountMenu() *fyne.Menu {
	var items []*fyne.MenuItem
	for _, session := range s.savedAccounts {
		username := session.Username
		item := fyne.NewMenuItem(username, func() { s.switchAccount(username) })
		if s.session != nil && accounts.Key(username) == accounts.Key(s.session.Username) {
			item.Checked = true
			item.Disabled = true
		}
		items = append(items, item)
	}
	if len(items) > 0 {
		items = append(items, fyne.NewMenuItemSeparator())
	}
	items = append(items, fyne.NewMenuItem("Add Another Account…", func() { s.switchAccount("Add another account…") }))
	manage := fyne.NewMenuItem("Manage Saved Accounts…", s.showSavedAccounts)
	manage.Disabled = len(s.savedAccounts) == 0
	items = append(items, manage)
	return fyne.NewMenu("Accounts", items...)
}

func (s *Screen) showAccountMenu() {
	if s.busy {
		return
	}
	widget.ShowPopUpMenuAtRelativePosition(s.accountMenu(), s.Window.Canvas(),
		fyne.NewPos(0, s.switchAccountButton.Size().Height), s.switchAccountButton)
}

func (s *Screen) hideAccountsDialog() {
	if s.accountsDialog != nil {
		s.accountsDialog.Hide()
		s.accountsDialog = nil
	}
	s.accountRemoveButtons = nil
}

func (s *Screen) showSavedAccounts() {
	if s.busy {
		return
	}
	s.hideAccountDialog()
	s.hideAccountsDialog()
	rows := column(8)
	for _, session := range s.savedAccounts {
		username := session.Username
		name := widget.NewLabel(username)
		singleLine(name)
		if s.session != nil && accounts.Key(username) == accounts.Key(s.session.Username) {
			name.TextStyle.Bold = true
		}
		remove := widget.NewButton("Remove…", func() { s.confirmRemoveAccount(username) })
		s.accountRemoveButtons = append(s.accountRemoveButtons, remove)
		rows.Add(container.NewBorder(nil, nil, nil, control(36, remove), name))
	}
	note := caption("Removing a saved account forgets its sign-in on this computer. Your installed apps stay on your iPhone.")
	note.Wrapping = fyne.TextWrapWord
	list := container.NewVScroll(rows)
	list.SetMinSize(fyne.NewSize(300, fyne.Min(220, rows.MinSize().Height)))
	s.accountsDialog = dialog.NewCustom("Saved Accounts", "Done", column(16, list, note), s.Window)
	current := s.accountsDialog
	current.SetOnClosed(func() {
		if s.accountsDialog == current {
			s.accountsDialog = nil
			s.accountRemoveButtons = nil
		}
	})
	s.accountsDialog.Show()
	s.accountsDialog.Resize(fyne.NewSize(fyne.Min(440, s.Window.Canvas().Size().Width-40), s.accountsDialog.MinSize().Height))
}

func (s *Screen) confirmRemoveAccount(username string) {
	if s.busy {
		return
	}
	dialog.ShowConfirm("Remove saved account?", fmt.Sprintf("Remove %s from this computer? Your installed apps will stay on your iPhone.", username), func(confirmed bool) {
		if confirmed && !s.busy {
			s.removeSavedAccount(username)
		}
	}, s.Window)
}

func (s *Screen) confirmForgetSavedAccount() {
	i := s.savedSelector.SelectedIndex()
	if s.busy || i < 0 || i >= len(s.savedAccounts) {
		return
	}
	username := s.savedAccounts[i].Username
	dialog.ShowConfirm("Remove saved account?", fmt.Sprintf("Remove %s from this computer? Your installed apps will stay on your iPhone.", username), func(confirmed bool) {
		if confirmed && !s.busy && s.savedSelector.Selected == username {
			s.forgetSavedAccount()
		}
	}, s.Window)
}
