package platform

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// codeObject is a signing unit. Frameworks/dylibs use the app's certificate
// without app entitlements; extensions get their own profile and entitlements.
// Contained code is signed first so enclosing seals record its final bytes.
type codeObject struct {
	Path, Executable, Identifier string
	Extension                    bool
	Entitlements                 string
	Sharing                      sharingRequest
	Networking                   networkRequest
	Capabilities                 capabilityRequest
	ExtensionPoint               string
}

func inspectCode(ctx context.Context, app appInfo) ([]codeObject, error) {
	objects := []codeObject{}
	executables := map[string]bool{filepath.Join(app.Path, app.Executable): true}
	ids := map[string]bool{strings.ToLower(app.BundleID): true}
	err := filepath.WalkDir(app.Path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return failure("Could not inspect app code")
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return failure("Linked app members are unsupported")
		}
		if d.IsDir() {
			if p == app.Path {
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".app", ".xpc":
				return failure("Nested executable apps are not yet supported")
			case ".appex":
				extension, err := inspectExtension(p, app)
				if err != nil {
					return err
				}
				if ids[strings.ToLower(extension.BundleID)] {
					return failure("App extensions must have unique bundle identifiers")
				}
				ids[strings.ToLower(extension.BundleID)] = true
				executable := filepath.Join(p, extension.Executable)
				executables[executable] = true
				objects = append(objects, codeObject{Path: p, Executable: executable, Identifier: extension.BundleID, Extension: true, Sharing: extension.Sharing, Networking: extension.Networking, Capabilities: extension.Capabilities, ExtensionPoint: extension.ExtensionPoint})
			case ".framework":
				if !frameworksDirectory(filepath.Dir(p), app.Path) {
					return failure("Framework must be embedded in a Frameworks directory")
				}
				data, err := readLimited(filepath.Join(p, "Info.plist"), 1<<20)
				if err != nil {
					return failure("Embedded framework Info.plist is missing")
				}
				info, err := dictionary(data)
				if err != nil {
					return failure("Embedded framework Info.plist is invalid")
				}
				executable, id := stringField(info, "CFBundleExecutable"), stringField(info, "CFBundleIdentifier")
				if !validText(executable) || executable == "." || executable == ".." || filepath.Base(executable) != executable || strings.ContainsAny(executable, "/\\:") || !bundlePattern.MatchString(id) || len(id) > 255 || stringField(info, "CFBundlePackageType") != "FMWK" {
					return failure("Unsupported embedded framework metadata")
				}
				binaryPath := filepath.Join(p, executable)
				if err = prepareLibraryArchitectures(binaryPath); err != nil {
					return fmt.Errorf("Embedded framework %s: %w", filepath.Base(p), err)
				}
				if err = inspectMachO(binaryPath, 6); err != nil {
					return fmt.Errorf("Embedded framework: %w", err)
				}
				executables[binaryPath] = true
				objects = append(objects, codeObject{Path: p, Executable: binaryPath, Identifier: id})
			}
			return nil
		}
		if executables[p] {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".dylib") {
			if !frameworksDirectory(filepath.Dir(p), app.Path) {
				return failure("Dynamic library must be embedded in a Frameworks directory")
			}
			if err = prepareLibraryArchitectures(p); err != nil {
				return fmt.Errorf("Embedded dynamic library %s: %w", filepath.Base(p), err)
			}
			if err = inspectMachO(p, 6); err != nil {
				return fmt.Errorf("Embedded dynamic library: %w", err)
			}
			objects = append(objects, codeObject{Path: p, Executable: p, Identifier: filepath.Base(p)})
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return failure("Could not inspect app member")
		}
		var magic [4]byte
		_, _ = io.ReadFull(f, magic[:])
		f.Close()
		switch binary.LittleEndian.Uint32(magic[:]) {
		case 0xfeedfacf, 0xfeedface, 0xcffaedfe, 0xcefaedfe, 0xbebafeca, 0xcafebabe, 0xbfbafeca, 0xcafebabf:
			return failure("Executable code outside a supported framework or dylib is unsupported")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = inspectMachO(filepath.Join(app.Path, app.Executable), 2); err != nil {
		return nil, err
	}
	sort.Slice(objects, func(i, j int) bool {
		left, right := strings.Count(objects[i].Path, string(filepath.Separator)), strings.Count(objects[j].Path, string(filepath.Separator))
		if left != right {
			return left > right
		}
		return objects[i].Path < objects[j].Path
	})
	return objects, nil
}

// Older injected frameworks contain armv7 alongside arm64. All supported phones
// run arm64; discard obsolete 32-bit library slices in the extracted copy before
// signing. Executable bundles still require every architecture to be supported.
func prepareLibraryArchitectures(path string) error {
	b, err := readLimited(path, 512<<20)
	if err != nil {
		return err
	}
	slices, err := machSlices(b)
	if err != nil {
		return err
	}
	legacy := false
	var arm64 [][]byte
	for _, slice := range slices {
		if len(slice.Data) < 32 {
			return failure("Truncated embedded library")
		}
		switch binary.LittleEndian.Uint32(slice.Data[4:]) {
		case 12:
			legacy = true
		case 0x100000c:
			arm64 = append(arm64, slice.Data)
		default:
			return failure("Embedded library contains an unsupported architecture")
		}
	}
	if !legacy {
		return nil
	}
	if len(arm64) != 1 {
		return failure("Legacy universal library must contain one arm64 slice")
	}
	if err = validateMachOType(arm64[0], 6); err != nil {
		return err
	}
	if err = os.WriteFile(path, arm64[0], 0600); err != nil {
		return failure("Could not prepare arm64 library")
	}
	return nil
}

func frameworksDirectory(dir, main string) bool {
	if filepath.Base(dir) != "Frameworks" {
		return false
	}
	parent := filepath.Dir(dir)
	return parent == main || strings.HasSuffix(parent, ".framework") || strings.HasSuffix(parent, ".appex")
}

func inspectMachO(p string, fileType uint32) error {
	b, err := readLimited(p, 512<<20)
	if err != nil {
		return failure("Bundle code is missing or exceeds the size limit")
	}
	if err = validateMachOType(b, fileType); err != nil {
		return err
	}
	if fileType == 6 {
		request, err := readSharingRequest(p)
		if err != nil {
			return err
		}
		if requiresSharing(request) {
			return failure("Sharing entitlements belong on executable app bundles, not libraries")
		}
	}
	return nil
}
