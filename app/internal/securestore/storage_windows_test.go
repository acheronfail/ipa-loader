//go:build windows

package securestore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDPAPIAndBoundedStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "value.dpapi")
	secret := []byte("synthetic private key material")
	if err := Write(path, secret); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err != nil {
		t.Fatal(err)
	}
	plain, err := Read(path, len(secret))
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("DPAPI did not round trip", err)
	}
	if _, err = Read(path, len(secret)-1); err == nil {
		t.Fatal("oversize plaintext accepted")
	}
	if _, err = Unprotect(secret); err == nil {
		t.Fatal("plaintext fallback accepted")
	}
	if err = Write(path, []byte("replacement")); err != nil {
		t.Fatal("atomic replacement failed", err)
	}
	plain, err = Read(path, 100)
	if err != nil || string(plain) != "replacement" {
		t.Fatal("replacement did not round trip", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary secret file retained", err)
	}
}

func TestWindowsStorageRefusesBroadACLAndHardlinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(root, "value.dpapi")
	if err := Write(path, []byte("synthetic secret")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias.dpapi")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 100); err == nil {
		t.Fatal("hard-linked secret file accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = Read(path, 100); err == nil {
		t.Fatal("world-readable secret file accepted")
	}
	if err = Write(path, []byte("replacement")); err == nil {
		t.Fatal("unsafe destination overwritten")
	}
}

func TestWindowsPrivateWorkspaceAndExclusiveFiles(t *testing.T) {
	root, err := MkdirTemp(t.TempDir(), "workspace-")
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckDir(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "signing-material")
	file, err := CreatePrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("synthetic key")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = CheckFile(path); err != nil {
		t.Fatal(err)
	}
	if file, err = CreatePrivate(path); err == nil {
		file.Close()
		t.Fatal("exclusive file creation overwrote signing material")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "synthetic key" {
		t.Fatal("exclusive create changed existing data", err)
	}
	// Ordinary Go writes inherit only this user's permissions from the checked
	// workspace. This is the same path used for transient signing diagnostics.
	inherited := filepath.Join(root, "diagnostic")
	if err = os.WriteFile(inherited, []byte("synthetic diagnostic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = CheckFile(inherited); err != nil {
		t.Fatal("safe inherited file ACL rejected", err)
	}
	if err = EnsureDir(filepath.Join(root, "nested")); err != nil {
		t.Fatal(err)
	}
	if err = CheckDir(filepath.Join(root, "nested")); err != nil {
		t.Fatal(err)
	}
	if _, err = MkdirTemp(root, "../escape"); err == nil {
		t.Fatal("workspace prefix escaped its parent")
	}
}
