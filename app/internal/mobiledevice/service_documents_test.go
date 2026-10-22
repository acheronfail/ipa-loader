//go:build windows || linux || darwin

package mobiledevice

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestWindowsReadOnlyDocumentProtocol(t *testing.T) {
	for _, kind := range []string{"documents", "developer container", "denied", "not complete", "directory symlink", "file symlink", "oversize", "short file", "grew", "read denied", "malformed stat"} {
		t.Run(kind, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				request, err := readDevicePlist(server)
				if err != nil {
					done <- err
					return
				}
				command := "VendDocuments"
				if kind == "developer container" {
					command = "VendContainer"
				}
				if request["Command"] != command || request["Identifier"] != "org.example.owned" {
					done <- fmt.Errorf("unexpected house-arrest request")
					return
				}
				response := map[string]any{"Status": "Complete"}
				if kind == "denied" {
					response = map[string]any{"Error": "private response must not escape"}
				}
				if kind == "not complete" {
					response = map[string]any{"Status": "Pending"}
				}
				body, _ := plist.Marshal(response, plist.XMLFormat)
				packet := make([]byte, 4+len(body))
				binary.BigEndian.PutUint32(packet, uint32(len(body)))
				copy(packet[4:], body)
				for _, b := range packet {
					if _, err := server.Write([]byte{b}); err != nil {
						done <- err
						return
					}
				}
				if kind == "denied" || kind == "not complete" {
					done <- nil
					return
				}
				payload := []byte("proof")
				if kind == "short file" {
					payload = []byte("pro")
				}
				if kind == "grew" {
					payload = []byte("proof+")
				}
				offset := 0
				for {
					seq, operation, data, err := readAFCRequest(server)
					if err != nil {
						if err == io.EOF || err == io.ErrClosedPipe {
							done <- nil
						} else {
							done <- err
						}
						return
					}
					op := uint64(2)
					var reply []byte
					switch operation {
					case 10:
						filename := strings.TrimSuffix(string(data), "\x00")
						mode := "S_IFREG"
						if filename == "Documents" {
							mode = "S_IFDIR"
						} else if filename != "Documents/proof.json" {
							done <- fmt.Errorf("read outside requested document")
							return
						}
						if kind == "directory symlink" && filename == "Documents" || kind == "file symlink" && filename != "Documents" {
							mode = "S_IFLNK"
						}
						size := 5
						if kind == "oversize" {
							size = maxDocumentBytes + 1
						}
						reply = []byte(fmt.Sprintf("st_ifmt\x00%s\x00st_size\x00%d\x00", mode, size))
						if kind == "malformed stat" {
							reply = []byte("st_ifmt\x00S_IFREG\x00odd\x00")
						}
					case 13:
						if len(data) < 9 || binary.LittleEndian.Uint64(data) != 1 || string(data[8:]) != "Documents/proof.json\x00" {
							done <- fmt.Errorf("document open was not read only")
							return
						}
						op = 14
						reply = afcNumber(7)
					case 15:
						if kind == "read denied" {
							op = 1
							reply = afcNumber(8)
							break
						}
						requested := int(binary.LittleEndian.Uint64(data[8:]))
						n := len(payload) - offset
						if n > 2 {
							n = 2
						}
						if n > requested {
							n = requested
						}
						reply = payload[offset : offset+n]
						offset += n
					case 20:
						op = 1
						reply = afcNumber(0)
					default:
						done <- fmt.Errorf("document reader issued mutation or unexpected operation %d", operation)
						return
					}
					for _, b := range afcReply(seq, op, reply) {
						if _, err := server.Write([]byte{b}); err != nil {
							done <- nil
							return
						}
					}
					if operation == 20 {
						done <- nil
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			body, err := readWindowsAppDocument(ctx, client, "org.example.owned", "proof.json", DocumentOptions{DeveloperContainer: kind == "developer container"})
			want := kind == "documents" || kind == "developer container"
			if (err == nil) != want {
				t.Fatal("document protocol result incorrect", err)
			}
			if want && string(body) != "proof" {
				t.Fatal("document bytes changed")
			}
			if err != nil && strings.Contains(err.Error(), "private response") {
				t.Fatal("raw response leaked")
			}
			client.Close()
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestWindowsDocumentPathValidation(t *testing.T) {
	for _, path := range []string{"", "../outside", "a/../outside", "/absolute", "a\\b", "a:b", "a\x00b", "a//b", "a/./b", "a\nb", "Documents/../../Library"} {
		if err := validateDocumentRequest("org.example.owned", path); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	for _, bundle := range []string{"", "org/owned", "org.example\n", "org..owned", "a"} {
		if err := validateDocumentRequest(bundle, "proof.json"); err == nil {
			t.Fatal("unsafe bundle identifier accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WindowsReadAppDocument(ctx, "unused", "org.example.owned", "proof.json", DocumentOptions{}); err != context.Canceled {
		t.Fatal("cancelled request accessed device", err)
	}
}

func TestWindowsDocumentBlockedCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requested := make(chan struct{})
	go func() { _, _ = readDevicePlist(server); close(requested) }()
	done := make(chan error, 1)
	go func() {
		_, err := readWindowsAppDocument(ctx, client, "org.example.owned", "proof.json", DocumentOptions{})
		done <- err
	}()
	<-requested
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal("blocked document request lost cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked document request ignored cancellation")
	}
}

func TestWindowsSelectedOwnedSharingProofReadOnly(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_WINDOWS_DOCUMENT_PROOF") != "1" {
		t.Skip("explicit owned SharingTest Documents/sharing-proof.json read only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	devices, err := WindowsDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var selected *WindowsDevice
	for i := range devices {
		if devices[i].Name == selectedTestDeviceName(t) {
			if selected != nil && selected.UDID != devices[i].UDID {
				t.Fatal("More than one selected test phone connected")
			}
			selected = &devices[i]
		}
	}
	if selected == nil {
		t.Fatal("selected test phone is not connected")
	}
	data, err := WindowsReadAppDocument(ctx, selected.UDID, "org.ipaloader.sharingtest", "sharing-proof.json", DocumentOptions{DeveloperContainer: true})
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		Build     string `json:"build"`
		Counter   int    `json:"counter"`
		AllOK     bool   `json:"all_ok"`
		Extension bool   `json:"extension"`
	}
	if json.Unmarshal(data, &proof) != nil || proof.Build == "" || proof.Extension {
		t.Fatal("Owned main-app sharing proof is invalid")
	}
	t.Logf("Read-only SharingTest proof: build=%s counter=%d all_ok=%t", proof.Build, proof.Counter, proof.AllOK)
	if proof.Counter != 2 || !proof.AllOK {
		t.Fatal("Expected preserved sharing counter or stores did not match")
	}
}
