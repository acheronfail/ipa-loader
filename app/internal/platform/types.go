// Package platform implements the narrow, validated single-app installation path.
package platform

type Device struct {
	// ID identifies the selected device; UDID is its hardware identifier.
	ID, Name, UDID, Transport, Model, OSVersion string
}
type Progress struct {
	Fraction float64
	Message  string
}
type Result struct {
	ProfileRefreshed         bool
	CompletionMessage        string
	BundleID, Version, Build string
	Installed, Launched      bool
	// Submitted is deliberately separate from confirmed installation: cancelling
	// the local transport cannot undo work already handed to the phone.
	InstallSubmitted bool
	WorkDir          string
}
