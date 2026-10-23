package ipa

import "sort"

type Extension struct {
	Name, BundleID, Path, Point, Summary string
}

// A nil selection means no prior choice (include all). A non-nil selection with
// an empty Included list deliberately excludes every extension.
type ExtensionSelection struct {
	Included []string
}

func (s *ExtensionSelection) Includes(id string) bool {
	if s == nil {
		return true
	}
	for _, included := range s.Included {
		if included == id {
			return true
		}
	}
	return false
}

// Restrict remembered choices to this IPA. New extensions stay off when the
// user has already chosen a subset, including an explicitly empty subset.
func (i *Info) SelectedExtensions() *ExtensionSelection {
	selection := &ExtensionSelection{Included: []string{}}
	for _, extension := range i.Extensions {
		if i.Selection.Includes(extension.BundleID) {
			selection.Included = append(selection.Included, extension.BundleID)
		}
	}
	sort.Strings(selection.Included)
	return selection
}

func (i *Info) AppIDCount() int { return 1 + len(i.SelectedExtensions().Included) }

func (e Extension) Detail() string {
	switch e.Point {
	case "com.apple.Safari.web-extension":
		return "Safari extension"
	case "com.apple.app-migration":
		return "App data migration · included only when supported"
	case "com.apple.widgetkit-extension":
		return "Widgets"
	case "com.apple.share-services":
		return "Share sheet"
	case "com.apple.networkextension.packet-tunnel":
		return "VPN connection"
	case "com.apple.usernotifications.service", "com.apple.usernotifications.content-extension":
		return "Notification features"
	default:
		return "App extension"
	}
}
