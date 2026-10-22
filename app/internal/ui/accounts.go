//go:build !ios

package ui

import (
	"context"
	"errors"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
)

// Provisioning can consume IDs even if installation later fails. Refresh after
// either outcome without delaying the result or applying an old account's
// response after an account switch or a newer installation.
func (s *Screen) refreshAllowance(session *apple.Session) {
	if s.services.Teams == nil {
		return
	}
	s.allowanceGeneration++
	generation := s.allowanceGeneration
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		teams, err := s.services.Teams(ctx, session)
		fyne.Do(func() {
			if err != nil || s.session != session || s.allowanceGeneration != generation {
				return
			}
			for i, current := range s.teams {
				for _, updated := range teams {
					if current.ID == updated.ID {
						s.teams[i] = updated
						break
					}
				}
			}
			s.updateQuota()
		})
	}()
}

func (s *Screen) initAccounts() {
	s.savedSelector = widget.NewSelect(nil, func(value string) {
		if s.updatingAccounts || s.busy {
			return
		}
		s.loginNeedsPassword = false
		for _, session := range s.savedAccounts {
			if session.Username == value {
				s.username.SetText(value)
				s.password.SetText("")
				s.updateAccountContinuation()
				s.forgetAccount.Enable()
				return
			}
		}
		s.username.SetText("")
		s.password.SetText("")
		s.forgetAccount.Disable()
		s.updateAccountContinuation()
	})
	s.savedSelector.PlaceHolder = "Choose a saved account"
	s.continueAccount = widget.NewButton("Continue", func() {
		i := s.savedSelector.SelectedIndex()
		if !s.busy && i >= 0 && i < len(s.savedAccounts) {
			s.resumeAccount(s.savedAccounts[i])
		}
	})
	s.continueAccount.Importance = widget.HighImportance
	s.continueAccount.Hide()
	s.forgetAccount = widget.NewButton("Remove…", s.confirmForgetSavedAccount)
	s.savedRow = column(6, caption("Saved accounts"), container.NewBorder(nil, nil, nil, control(40, s.forgetAccount), control(40, s.savedSelector)), s.continueAccount)
	s.savedRow.Hide()
}

func (s *Screen) applySavedAccounts(state accounts.Snapshot) {
	s.savedAccounts = state.Sessions
	s.updatingAccounts = true
	defer func() { s.updatingAccounts = false }()
	options := make([]string, 0, len(state.Sessions)+1)
	for _, session := range state.Sessions {
		options = append(options, session.Username)
	}
	options = append(options, "Add another account…")
	s.savedSelector.Options = options
	s.savedSelector.ClearSelected()
	username := s.username.Text
	if s.session != nil {
		username = s.session.Username
	}
	for _, session := range state.Sessions {
		if accounts.Key(session.Username) == accounts.Key(username) {
			s.savedSelector.SetSelected(session.Username)
		}
	}
	s.savedSelector.Refresh()
	if len(state.Sessions) > 0 {
		s.savedRow.Show()
	} else {
		s.savedRow.Hide()
	}
	s.updateQuota()
	if s.busy || s.savedSelector.SelectedIndex() < 0 {
		s.forgetAccount.Disable()
	} else {
		s.forgetAccount.Enable()
	}
	s.updateAccountContinuation()
	s.root.Refresh()
}

func (s *Screen) loadAccounts() {
	s.setBusy(true)
	s.accountStatus.SetText("Checking saved accounts…")
	s.accountStatus.Show()
	go func() {
		state, err := s.services.Accounts.Load()
		fyne.Do(func() {
			s.setBusy(false)
			s.accountStatus.Hide()
			if err != nil {
				s.accountStatus.SetText("Saved accounts could not be opened. You can still sign in for this run.\n" + err.Error())
				s.accountStatus.Show()
				return
			}
			s.applySavedAccounts(state)
			for _, session := range state.Sessions {
				if accounts.Key(session.Username) == accounts.Key(state.Active) {
					s.resumeAccount(session)
					return
				}
			}
		})
	}()
}

// Revalidate against Apple before enabling installation: stored sessions may
// expire or be bound to a local authentication identity that has changed.
func (s *Screen) resumeAccount(session *apple.Session) {
	if s.busy || s.services.Accounts == nil {
		return
	}
	current := s.session
	if current == nil {
		s.returnToLogin()
		s.username.SetText(session.Username)
		s.password.SetText("")
	} else {
		s.hideAccountDialog()
		s.hideAccountsDialog()
		s.setStatus("Switching accounts…")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.cancel = cancel
	s.setBusy(true)
	s.accountStatus.SetText("Signing in with your saved account…")
	s.accountStatus.Show()
	go func() {
		teams, err := s.services.Teams(ctx, session)
		if err == nil && len(teams) == 0 {
			err = errors.New("Apple did not return a developer team for this account")
		}
		var saveError error
		if err == nil && ctx.Err() == nil {
			saveError = s.services.Accounts.Select(session.Username)
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		fyne.Do(func() {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			s.setBusy(false)
			if err != nil {
				if current != nil {
					s.setStatus("Couldn’t switch accounts. Your current account is still signed in.")
					dialog.ShowInformation("Couldn’t Switch Accounts", "You’re still signed in as "+current.Username+".\n\n"+friendly(err), s.Window)
					return
				}
				s.loginNeedsPassword = true
				s.updateAccountContinuation()
				s.accountStatus.SetText("Couldn’t reconnect to this account. Sign in again to continue.\n" + friendly(err))
				s.accountStatus.Show()
				s.Window.Canvas().Focus(s.password)
				return
			}
			s.showAccount(session, teams)
			s.applySavedAccounts(accounts.Snapshot{Sessions: s.savedAccounts})
			if saveError != nil {
				dialog.ShowInformation("Account selected", "You can use this account, but the last-used account could not be saved.\n"+saveError.Error(), s.Window)
			}
			s.Start()
		})
	}()
}

func (s *Screen) forgetSavedAccount() {
	i := s.savedSelector.SelectedIndex()
	if i >= 0 && i < len(s.savedAccounts) {
		s.removeSavedAccount(s.savedAccounts[i].Username)
	}
}

func (s *Screen) removeSavedAccount(username string) {
	if s.busy || s.services.Accounts == nil {
		return
	}
	s.setBusy(true)
	go func() {
		err := s.services.Accounts.Remove(username)
		var state accounts.Snapshot
		if err == nil {
			state, err = s.services.Accounts.Load()
		}
		fyne.Do(func() {
			s.setBusy(false)
			if err != nil {
				dialog.ShowError(err, s.Window)
				return
			}
			if s.session == nil || accounts.Key(s.session.Username) == accounts.Key(username) {
				s.returnToLogin()
				s.username.SetText("")
				s.applySavedAccounts(state)
				s.accountStatus.SetText("Saved account removed from this computer.")
				s.accountStatus.Show()
			} else {
				s.applySavedAccounts(state)
				if s.accountsDialog != nil {
					s.showSavedAccounts()
				}
			}
		})
	}()
}

// The account picker chooses an identity; Continue makes the next action
// explicit even when that identity was already selected before navigating back.
func (s *Screen) updateAccountContinuation() {
	if s.continueAccount == nil {
		return
	}
	i := s.savedSelector.SelectedIndex()
	selected := i >= 0 && i < len(s.savedAccounts) && !s.loginNeedsPassword
	if s.loginFields != nil {
		if selected {
			s.loginFields.Hide()
		} else {
			s.loginFields.Show()
		}
	}
	if !selected {
		s.continueAccount.Hide()
		return
	}
	s.continueAccount.Show()
	if s.busy {
		s.continueAccount.Disable()
	} else {
		s.continueAccount.Enable()
	}
}
