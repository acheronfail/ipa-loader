//go:build !ios

package ui

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"ipa-loader/app/internal/ipa"
)

func (s *Screen) loadExtensionChoices() {
	if s.extensionOptions == nil {
		return
	}
	if s.extensionDialog != nil {
		s.extensionDialog.Hide()
		s.extensionDialog = nil
	}
	s.extensionChoiceErr = nil
	if s.selected == nil {
		s.extensionOptions.Hide()
		return
	}
	info := s.selected
	index := s.team.SelectedIndex()
	if s.services.ExtensionSelection != nil && s.session != nil && index >= 0 && index < len(s.teams) {
		info.Selection, s.extensionChoiceErr = s.services.ExtensionSelection(s.session.Username, s.teams[index].ID, info.BundleID)
	}
	s.extensionOptions.Objects = nil
	s.extensionChecks = nil
	if s.extensionChoiceErr != nil {
		s.extensionOptions.Add(wrap(s.extensionChoiceErr.Error()))
		s.extensionOptions.Show()
		return
	}
	if len(info.Extensions) == 0 {
		s.extensionOptions.Hide()
		s.updateSelectedAppDetail()
		return
	}
	s.extensionCost = caption("")
	if len(info.Extensions) > 0 {
		s.extensionOptions.Add(widget.NewLabelWithStyle("Extensions", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
		for _, extension := range info.Extensions {
			check := widget.NewCheck("Include", nil)
			check.SetChecked(info.Selection.Includes(extension.BundleID))
			check.OnChanged = func(bool) {
				selection := &ipa.ExtensionSelection{Included: []string{}}
				for i, c := range s.extensionChecks {
					if c.Checked {
						selection.Included = append(selection.Included, info.Extensions[i].BundleID)
					}
				}
				info.Selection = selection
				s.updateExtensionCost()
			}
			s.extensionChecks = append(s.extensionChecks, check)
			name := wrap(extension.Name)
			name.TextStyle.Bold = true
			detail := caption(extension.Detail() + "\n" + extension.BundleID)
			detail.Wrapping = fyne.TextWrapBreak
			s.extensionOptions.Add(container.NewBorder(nil, nil, nil, check, column(2, name, detail)))
		}
	}
	s.updateExtensionCost()
	s.extensionOptions.Show()
	s.extensionOptions.Refresh()
}

func (s *Screen) updateExtensionCost() {
	if s.extensionCost == nil || s.selected == nil {
		return
	}
	count := s.selected.AppIDCount()
	label := "App ID"
	if count != 1 {
		label = "App IDs"
	}
	s.extensionCost.SetText(fmt.Sprintf("%d %s", count, label))
	s.updateSelectedAppDetail()
}

func (s *Screen) updateSelectedAppDetail() {
	if s.selected == nil {
		return
	}
	info := s.selected
	label := "App IDs"
	if info.AppIDCount() == 1 {
		label = "App ID"
	}
	s.appDetail.SetText(fmt.Sprintf("%s · build %s · %d %s\n%s", info.Version, info.Build, info.AppIDCount(), label, info.BundleID))
}
