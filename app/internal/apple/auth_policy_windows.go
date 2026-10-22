//go:build windows

package apple

// AltSign #61, published 2026-10-15, describes the Windows provider's identity
// and string-valued CPD. Credential-free probes verified that this identity
// reaches structured GSA responses where Mac/Xcode declarations receive 503.
func windowsAuthentication() bool { return true }
