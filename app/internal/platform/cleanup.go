package platform

import (
	"crypto/sha256"
	"os"
)

type ownedFile struct {
	path string
	info os.FileInfo
	hash [32]byte
}

func captureOwned(path string) (ownedFile, []byte, error) {
	s, e := os.Lstat(path)
	if e != nil || !privateFile(path, s) || s.Size() > 1<<20 {
		return ownedFile{}, nil, failure("Signing recovery file changed or has unsafe permissions")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return ownedFile{}, nil, failure("Could not inspect signing recovery file")
	}
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(s, after) {
		return ownedFile{}, nil, failure("Signing recovery file changed during inspection")
	}
	return ownedFile{path, s, sha256.Sum256(b)}, b, nil
}
func (s ownedFile) same(content bool) bool {
	st, e := os.Lstat(s.path)
	if e != nil || !os.SameFile(s.info, st) || !privateFile(s.path, st) {
		return false
	}
	if content {
		b, e := os.ReadFile(s.path)
		return e == nil && sha256.Sum256(b) == s.hash
	}
	return true
}
func (s ownedFile) remove(content bool) {
	if s.same(content) {
		_ = os.Remove(s.path)
	}
}
func exclusive(path string, data []byte) error {
	f, e := createPrivateFile(path)
	if e != nil {
		return failure("Could not create exclusive private signing file")
	}
	_, e = f.Write(data)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return failure("Could not write private signing file")
	}
	return nil
}
func mapField(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }
