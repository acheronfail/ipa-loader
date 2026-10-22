//go:build windows || linux || darwin

package mobiledevice

// Public protocol reference: libimobiledevice 1.4.0 house_arrest.c/h. A framed
// Command/Identifier plist must receive Status=Complete before the same stream
// becomes AFC. No upstream implementation is copied here.
import (
	"context"
	"errors"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxDocumentBytes = 1 << 20

var documentBundleID = regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)

type DocumentOptions struct {
	// DeveloperContainer explicitly requests VendContainer for development apps
	// without file sharing enabled. The reader still exposes only one validated
	// file below Documents, with no container listing or write operations.
	DeveloperContainer bool
}

// WindowsReadAppDocument reads exactly one requested app document. It starts an
// existing paired session and never pairs, enumerates containers, or writes.
func WindowsReadAppDocument(ctx context.Context, udid, bundleID, relative string, options DocumentOptions) ([]byte, error) {
	if err := validateDocumentRequest(bundleID, relative); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return nil, err
	}
	defer session.close()
	conn, err := session.service(ctx, "com.apple.mobile.house_arrest")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return readWindowsAppDocument(ctx, conn, bundleID, relative, options)
}

func validateDocumentRequest(bundleID, relative string) error {
	if len(bundleID) > 255 || !documentBundleID.MatchString(bundleID) {
		return errors.New("Select a valid app identifier before reading a document")
	}
	if relative == "" || len(relative) > 1024 || !utf8.ValidString(relative) || path.Clean(relative) != relative || strings.HasPrefix(relative, "/") || strings.ContainsAny(relative, "\\:\x00\r\n") {
		return errors.New("Select a clean relative document filename")
	}
	for _, part := range strings.Split(relative, "/") {
		if part == "." || part == ".." || part == "" {
			return errors.New("Document path cannot escape the app's Documents folder")
		}
		for _, r := range part {
			if r < 32 {
				return errors.New("Document path contains a control character")
			}
		}
	}
	return nil
}

func readWindowsAppDocument(ctx context.Context, conn net.Conn, bundleID, relative string, options DocumentOptions) ([]byte, error) {
	if err := validateDocumentRequest(bundleID, relative); err != nil {
		return nil, err
	}
	command := "VendDocuments"
	if options.DeveloperContainer {
		command = "VendContainer"
	}
	response, err := deviceExchange(ctx, conn, map[string]any{"Command": command, "Identifier": bundleID})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("The iPhone denied app document access; unlock it and check that the requested app permits this access")
	}
	if status, ok := response["Status"].(string); !ok || status != "Complete" {
		return nil, errors.New("The iPhone did not confirm app document access")
	}
	wire := &windowsAFC{conn: conn, ctx: ctx}
	defer wire.close()
	filename := "Documents/" + relative
	if err = checkDocumentPath(wire, filename); err != nil {
		return nil, err
	}
	size, err := wire.size(filename)
	if err != nil {
		return nil, err
	}
	if size > maxDocumentBytes {
		return nil, errors.New("Requested document exceeds the 1 MiB inspection limit")
	}
	handle, err := wire.open(filename, 1)
	if err != nil {
		return nil, err
	}
	defer wire.closeFile(handle)
	result := make([]byte, 0, int(size))
	buffer := make([]byte, 32<<10)
	for {
		remaining := int(size) - len(result) + 1
		if remaining < len(buffer) {
			buffer = buffer[:remaining]
		}
		n, err := wire.read(handle, buffer)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		result = append(result, buffer[:n]...)
		if len(result) > int(size) {
			return nil, errors.New("Requested document grew during inspection")
		}
	}
	if uint64(len(result)) != size {
		return nil, errors.New("Requested document changed size during inspection")
	}
	if err = checkDocumentPath(wire, filename); err != nil {
		return nil, err
	}
	after, err := wire.size(filename)
	if err != nil || after != size {
		return nil, errors.New("Requested document changed during inspection")
	}
	return result, nil
}

func checkDocumentPath(wire *windowsAFC, filename string) error {
	parts := strings.Split(filename, "/")
	for i := range parts {
		current := strings.Join(parts[:i+1], "/")
		op, body, err := wire.exchange(10, append([]byte(current), 0), nil)
		if err != nil {
			return err
		}
		if op != 2 || len(body) == 0 || body[len(body)-1] != 0 {
			return errors.New("Invalid app document file information")
		}
		fields := strings.Split(string(body[:len(body)-1]), "\x00")
		if len(fields)%2 != 0 {
			return errors.New("Invalid app document file information")
		}
		metadata := map[string]string{}
		for j := 0; j < len(fields); j += 2 {
			if _, exists := metadata[fields[j]]; exists {
				return errors.New("Duplicate app document file information")
			}
			metadata[fields[j]] = fields[j+1]
		}
		want := "S_IFDIR"
		if i == len(parts)-1 && filename != "Documents" {
			want = "S_IFREG"
		}
		if metadata["st_ifmt"] != want || metadata["LinkTarget"] != "" {
			return errors.New("Requested document path contains a link or unsupported file type")
		}
		if i == len(parts)-1 && filename != "Documents" {
			size, err := strconv.ParseUint(metadata["st_size"], 10, 64)
			if err != nil || size > maxDocumentBytes {
				return errors.New("Requested document size is invalid or exceeds 1 MiB")
			}
		}
	}
	return nil
}
