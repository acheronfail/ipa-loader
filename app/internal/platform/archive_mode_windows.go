//go:build windows

package platform

import (
	"encoding/binary"
	"io"
	"os"
)

// NTFS cannot retain the Unix executable bits set during signing. Restore the
// iOS archive modes from the file type; resources are readable, code executable.
func signedArchiveMode(path string, info os.FileInfo) (os.FileMode, error) {
	if info.IsDir() {
		return os.ModeDir | 0755, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	var head [4]byte
	_, err = io.ReadFull(file, head[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, err
	}
	switch binary.BigEndian.Uint32(head[:]) {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return 0755, nil
	}
	return 0644, nil
}
