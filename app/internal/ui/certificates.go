//go:build !ios

package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"ipa-loader/app/internal/apple"
)

type certificateRecovery struct {
	session      *apple.Session
	team         string
	cancel       context.CancelFunc
	running      bool
	manager      *dialog.CustomDialog
	confirmation *dialog.ConfirmDialog
	selector     *widget.Select
	revoke       *widget.Button
	selected     *apple.DevelopmentCertificate
	quotaReached bool
}

func (s *Screen) updateCertificateAction() {
	if s.session == nil || s.services.DevelopmentCertificates == nil || s.services.RevokeDevelopmentCertificate == nil {
		s.manageCertificates.Hide()
		return
	}
	s.manageCertificates.Show()
	index := s.team.SelectedIndex()
	if s.busy || index < 0 || index >= len(s.teams) {
		s.manageCertificates.Disable()
	} else {
		s.manageCertificates.Enable()
	}
}

func (s *Screen) currentCertificateRecovery(r *certificateRecovery) bool {
	index := s.team.SelectedIndex()
	return r != nil && s.certificateRecovery == r && s.session == r.session && index >= 0 && index < len(s.teams) && s.teams[index].ID == r.team
}

func (s *Screen) dismissCertificateRecovery() {
	r := s.certificateRecovery
	s.certificateRecovery = nil
	if r == nil {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.manager != nil {
		r.manager.Hide()
		r.manager = nil
	}
	if r.confirmation != nil {
		r.confirmation.Hide()
		r.confirmation = nil
	}
	if r.running {
		s.setBusy(false)
	}
}

func (s *Screen) showCertificateQuota(session *apple.Session, team string) {
	if s.services.DevelopmentCertificates == nil || s.services.RevokeDevelopmentCertificate == nil {
		return
	}
	r := &certificateRecovery{session: session, team: team, quotaReached: true}
	s.certificateRecovery = r
	if !s.currentCertificateRecovery(r) {
		s.dismissCertificateRecovery()
		return
	}
	s.setStatus("Apple's development certificate limit has been reached. Manage certificates to choose one to revoke, then retry installation.")
	s.updateCertificateAction()
}

func (s *Screen) manageDevelopmentCertificates() {
	index := s.team.SelectedIndex()
	if s.busy || s.session == nil || index < 0 || index >= len(s.teams) || s.services.DevelopmentCertificates == nil || s.services.RevokeDevelopmentCertificate == nil {
		return
	}
	r := s.certificateRecovery
	if !s.currentCertificateRecovery(r) {
		s.dismissCertificateRecovery()
		r = &certificateRecovery{session: s.session, team: s.teams[index].ID}
		s.certificateRecovery = r
	}
	if r.manager != nil || r.confirmation != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	r.cancel = cancel
	r.running = true
	s.cancel = cancel
	s.setBusy(true)
	s.setStatus("Loading development certificates…")
	go func() {
		certificates, err := s.services.DevelopmentCertificates(ctx, r.session, r.team)
		if err == nil {
			err = ctx.Err()
		}
		fyne.Do(func() {
			defer cancel()
			if !s.currentCertificateRecovery(r) {
				return
			}
			r.running = false
			r.cancel = nil
			s.setBusy(false)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					s.setStatus("Certificate lookup cancelled.")
				} else {
					s.setStatus("Could not load certificates. " + friendly(err))
				}
				return
			}
			if len(certificates) == 0 {
				message := "This developer team has no active development certificates."
				if r.quotaReached {
					message += " Retry installation or check your developer account."
				}
				s.setStatus(message)
				return
			}
			s.showCertificateManager(r, certificates)
		})
	}()
}

func certificateDescription(c apple.DevelopmentCertificate) string {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = "Development certificate"
	}
	date := func(value time.Time) string {
		if value.IsZero() {
			return "Not provided by Apple"
		}
		return value.Local().Format("2 Jan 2006, 15:04 MST")
	}
	kind := strings.TrimSpace(c.Kind)
	if kind == "" {
		kind = "Not provided by Apple"
	}
	return fmt.Sprintf("%s\nType: %s\nSerial: %s\nIssued: %s\nExpires: %s", name, kind, c.Serial, date(c.IssuedAt), date(c.ExpiresAt))
}

func (s *Screen) showCertificateManager(r *certificateRecovery, certificates []apple.DevelopmentCertificate) {
	if !s.currentCertificateRecovery(r) {
		return
	}
	r.selected = nil
	detail := wrap("Select one certificate to review its issue date, expiry and serial number.")
	r.revoke = widget.NewButton("Revoke", func() { s.confirmCertificateRevocation(r) })
	r.revoke.Importance = widget.DangerImportance
	r.revoke.Disable()
	options := make([]string, len(certificates))
	for i, c := range certificates {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			name = "Development certificate"
		}
		label := []rune(name)
		if len(label) > 18 {
			name = string(label[:17]) + "…"
		}
		serial := c.Serial
		if len(serial) > 12 {
			serial = "…" + serial[len(serial)-12:]
		}
		kind := strings.TrimSpace(c.Kind)
		if kind != "" {
			name = kind + ": " + name
		}
		options[i] = fmt.Sprintf("%d. %s · %s", i+1, name, serial)
	}
	var content *fyne.Container
	r.selector = widget.NewSelect(options, func(string) {
		if !s.currentCertificateRecovery(r) || r.manager == nil {
			return
		}
		index := r.selector.SelectedIndex()
		r.selected = nil
		r.revoke.Disable()
		if index < 0 || index >= len(certificates) {
			return
		}
		selected := certificates[index]
		if strings.TrimSpace(selected.Serial) == "" {
			return
		}
		r.selected = &selected
		detail.SetText(certificateDescription(selected))
		r.revoke.Enable()
		if content != nil {
			content.Refresh()
		}
		r.manager.Refresh()
	})
	r.selector.PlaceHolder = "Choose a certificate"
	content = container.NewVBox(
		wrap("Choose a certificate you no longer need. Revoking it invalidates provisioning profiles that contain it and can stop apps signed with those profiles from opening."),
		r.selector, detail)
	scroll := container.NewVScroll(content)
	scroll.SetMinSize(fyne.NewSize(0, 140))
	r.manager = dialog.NewCustom("Development certificates", "Close", scroll, s.Window)
	manager := r.manager
	manager.SetButtons([]fyne.CanvasObject{widget.NewButton("Close", manager.Hide), r.revoke})
	manager.SetOnClosed(func() {
		if r.manager == manager {
			r.manager = nil
			r.selected = nil
		}
	})
	size := s.Window.Canvas().Size()
	manager.Resize(fyne.NewSize(fyne.Min(540, size.Width-24), fyne.Min(420, size.Height-48)))
	manager.Show()
	s.setStatus("Review the certificates and choose one to revoke, or close without making changes.")
}

func (s *Screen) confirmCertificateRevocation(r *certificateRecovery) {
	if s.busy || !s.currentCertificateRecovery(r) || r.manager == nil || r.selected == nil {
		return
	}
	selected := *r.selected
	// Closing the manager clears its selection. The confirmation retains exactly
	// the reviewed value; account/team checks run again before any request.
	manager := r.manager
	manager.Hide()
	var confirmation *dialog.ConfirmDialog
	confirmation = dialog.NewConfirm("Revoke this development certificate?", certificateDescription(selected)+"\n\nProvisioning profiles containing this certificate become invalid. Apps signed with those profiles may stop opening. This cannot be undone.", func(confirmed bool) {
		if r.confirmation != confirmation {
			return
		}
		r.confirmation = nil
		if !confirmed || s.busy || !s.currentCertificateRecovery(r) {
			return
		}
		s.revokeDevelopmentCertificate(r, selected)
	}, s.Window)
	r.confirmation = confirmation
	r.confirmation.SetConfirmText("Revoke")
	r.confirmation.SetDismissText("Cancel")
	r.confirmation.SetConfirmImportance(widget.DangerImportance)
	r.confirmation.Show()
}

func (s *Screen) revokeDevelopmentCertificate(r *certificateRecovery, selected apple.DevelopmentCertificate) {
	if s.busy || !s.currentCertificateRecovery(r) || selected.Serial == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	r.cancel = cancel
	r.running = true
	s.cancel = cancel
	s.setBusy(true)
	s.setStatus("Revoking the selected development certificate…")
	go func() {
		err := s.services.RevokeDevelopmentCertificate(ctx, r.session, r.team, selected)
		fyne.Do(func() {
			defer cancel()
			if !s.currentCertificateRecovery(r) {
				return
			}
			r.running = false
			r.cancel = nil
			s.setBusy(false)
			if err != nil {
				s.setStatus("Revocation was not confirmed. Refresh Manage certificates before choosing another action. " + friendly(err))
				s.log("Certificate revocation was not confirmed; no automatic retry or further revocation was attempted.")
				return
			}
			s.dismissCertificateRecovery()
			message := "Certificate revoked."
			if r.quotaReached {
				message += " Click Install App to retry installation."
			}
			s.setStatus(message)
			s.log("Selected certificate revoked: " + selected.Serial + ".")
		})
	}()
}
