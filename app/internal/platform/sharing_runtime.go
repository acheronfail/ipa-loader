package platform

import (
	"bytes"
	"embed"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
)

//go:embed compat/*
var sharingSource embed.FS

const sharingLibraryName = "IPALoaderSharingCompat-v1.dylib"
const sharingLibraryLoadPath = "@executable_path/Frameworks/" + sharingLibraryName

func (e *engine) buildSharingLibrary() (string, error) {
	if e.host == nil {
		return "", failure("Application host is not configured")
	}
	return e.host.sharingLibrary(e)
}

func (e *engine) buildDarwinSharingLibrary() (string, error) {
	directory := filepath.Join(e.work, "sharing-build")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", failure("Could not prepare sharing adapter build")
	}
	for _, name := range []string{"sharing.m", "fishhook.c", "fishhook.h", "LICENSE.fishhook"} {
		b, err := sharingSource.ReadFile("compat/" + name)
		if err != nil {
			return "", failure("Sharing adapter source is missing")
		}
		if err = os.WriteFile(filepath.Join(directory, name), b, 0600); err != nil {
			return "", failure("Could not prepare sharing adapter source")
		}
	}
	sdk, err := e.command("sharing-sdk", "xcrun", "--sdk", "iphoneos", "--show-sdk-path")
	if err != nil || !validText(strings.TrimSpace(string(sdk))) {
		return "", failure("An iPhoneOS SDK is required for sharing support")
	}
	output := filepath.Join(directory, sharingLibraryName)
	_, err = e.command("sharing-build", "xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios12.0", "-isysroot", strings.TrimSpace(string(sdk)), "-dynamiclib", "-fobjc-arc", "-O2", "-framework", "Foundation", "-framework", "Security", "-Wl,-no_adhoc_codesign", "-Wl,-install_name,@rpath/"+sharingLibraryName, filepath.Join(directory, "sharing.m"), filepath.Join(directory, "fishhook.c"), "-o", output)
	if err != nil {
		return "", failure("Could not build the shared-storage compatibility adapter")
	}
	if err = inspectMachO(output, 6); err != nil {
		return "", err
	}
	return output, nil
}

// addSharingLoadCommand uses existing zero header padding only. It never moves
// sections, edits instructions or bypasses encryption. Insufficient space is an
// explicit unsupported input, to be addressed by a future relayout implementation.
func addSharingLoadCommand(binaryData []byte) ([]byte, error) {
	b := binaryData
	if len(b) < 32 || binary.LittleEndian.Uint32(b) != 0xfeedfacf || binary.LittleEndian.Uint32(b[4:]) != 0x100000c || binary.LittleEndian.Uint32(b[8:]) != 0 || binary.LittleEndian.Uint32(b[12:]) != 2 {
		return nil, failure("Sharing runtime currently requires a thin arm64 executable without pointer authentication")
	}
	count, size := binary.LittleEndian.Uint32(b[16:]), binary.LittleEndian.Uint32(b[20:])
	if count > 100000 || uint64(size) > uint64(len(b)-32) {
		return nil, failure("Invalid Mach-O commands for sharing support")
	}
	end, offset, firstData := 32+int(size), 32, len(b)
	for i := uint32(0); i < count; i++ {
		if offset+8 > end {
			return nil, failure("Truncated Mach-O commands for sharing support")
		}
		cmd, n := binary.LittleEndian.Uint32(b[offset:]), int(binary.LittleEndian.Uint32(b[offset+4:]))
		if n < 8 || n%8 != 0 || n > end-offset {
			return nil, failure("Invalid Mach-O command size for sharing support")
		}
		c := b[offset : offset+n]
		if cmd == 0xc {
			if n < 24 {
				return nil, failure("Invalid dynamic-library command")
			}
			start := uint64(binary.LittleEndian.Uint32(c[8:]))
			if start < 24 || start >= uint64(n) {
				return nil, failure("Invalid dynamic-library name")
			}
			stop := bytes.IndexByte(c[start:], 0)
			if stop < 0 {
				return nil, failure("Unterminated dynamic-library name")
			}
			if string(c[start:start+uint64(stop)]) == sharingLibraryLoadPath {
				return append([]byte(nil), b...), nil
			}
		}
		if cmd == 0x19 {
			if n < 72 {
				return nil, failure("Invalid Mach-O segment for sharing support")
			}
			sections := uint64(binary.LittleEndian.Uint32(c[64:]))
			if sections > uint64(n-72)/80 {
				return nil, failure("Invalid Mach-O section table")
			}
			fileOffset := binary.LittleEndian.Uint64(c[40:])
			if fileOffset > 0 && fileOffset < uint64(firstData) {
				firstData = int(fileOffset)
			}
			for j := uint64(0); j < sections; j++ {
				section := c[72+80*j:]
				flags := binary.LittleEndian.Uint32(section[64:]) & 255
				if flags == 1 || flags == 0xc || flags == 0x12 {
					continue
				}
				position := uint64(binary.LittleEndian.Uint32(section[48:]))
				if position > 0 && position < uint64(firstData) {
					firstData = int(position)
				}
			}
		}
		offset += n
	}
	commandSize := (24 + len(sharingLibraryLoadPath) + 1 + 7) &^ 7
	if offset != end || firstData == len(b) || end > firstData || commandSize > firstData-end || commandSize > len(b)-end {
		return nil, failure("This app has insufficient Mach-O header space for sharing support")
	}
	for _, value := range b[end : end+commandSize] {
		if value != 0 {
			return nil, failure("This app's Mach-O header padding is occupied")
		}
	}
	result := append([]byte(nil), b...)
	command := result[end : end+commandSize]
	binary.LittleEndian.PutUint32(command, 0xc)
	binary.LittleEndian.PutUint32(command[4:], uint32(commandSize))
	binary.LittleEndian.PutUint32(command[8:], 24)
	binary.LittleEndian.PutUint32(command[16:], 1<<16)
	binary.LittleEndian.PutUint32(command[20:], 1<<16)
	copy(command[24:], sharingLibraryLoadPath)
	binary.LittleEndian.PutUint32(result[16:], count+1)
	binary.LittleEndian.PutUint32(result[20:], size+uint32(commandSize))
	return result, nil
}
