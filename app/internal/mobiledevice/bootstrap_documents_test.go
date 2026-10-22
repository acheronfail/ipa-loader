//go:build windows || linux || darwin

package mobiledevice

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestBootstrapDocumentCommitRequiresVerifiedBytes(t *testing.T) {
	for _, kind := range []string{"complete", "corrupt readback", "wrong size", "linked Documents", "short source", "denied", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			committed := false
			go func() {
				defer server.Close()
				request, err := readDevicePlist(server)
				if err != nil {
					done <- err
					return
				}
				if request["Command"] != "VendDocuments" || request["Identifier"] != "org.ipaloader.ios.ABCDE12345" {
					done <- fmt.Errorf("wrong app")
					return
				}
				response := map[string]any{"Status": "Complete"}
				if kind == "denied" {
					response = map[string]any{"Error": "Denied"}
				}
				if err = sendDevicePlist(server, response); err != nil {
					done <- err
					return
				}
				if kind == "denied" {
					done <- nil
					return
				}
				var stored []byte
				offset := 0
				for {
					seq, op, data, err := readAFCRequest(server)
					if err != nil {
						if err == io.EOF || err == io.ErrClosedPipe {
							done <- nil
						} else {
							done <- err
						}
						return
					}
					responseOp := uint64(1)
					reply := afcNumber(0)
					switch op {
					case 10:
						responseOp = 2
						if string(data) == "Documents\x00" {
							mode := "S_IFDIR"
							if kind == "linked Documents" {
								mode = "S_IFLNK"
							}
							reply = []byte("st_ifmt\x00" + mode + "\x00st_size\x000\x00")
						} else {
							size := len(stored)
							if kind == "wrong size" {
								size++
							}
							reply = []byte(fmt.Sprintf("st_ifmt\x00S_IFREG\x00st_size\x00%d\x00", size))
						}
					case 8:
						if string(data) != "Documents/IPALoaderBootstrap.json.incoming\x00" {
							done <- fmt.Errorf("unexpected delete")
							return
						}
					case 13:
						if string(data[8:]) != "Documents/IPALoaderBootstrap.json.incoming\x00" {
							done <- fmt.Errorf("unexpected open")
							return
						}
						responseOp = 14
						reply = afcNumber(7)
						offset = 0
					case 16:
						stored = append(stored, data[8:]...)
					case 20:
					case 15:
						responseOp = 2
						n := len(stored) - offset
						requested := int(binary.LittleEndian.Uint64(data[8:]))
						if n > requested {
							n = requested
						}
						reply = append([]byte(nil), stored[offset:offset+n]...)
						offset += n
						if kind == "corrupt readback" && len(reply) > 0 {
							reply[0] ^= 1
						}
					case 24:
						if string(data) != "Documents/IPALoaderBootstrap.json.incoming\x00Documents/IPALoaderBootstrap.json\x00" {
							done <- fmt.Errorf("unexpected commit destination")
							return
						}
						committed = true
					default:
						done <- fmt.Errorf("unexpected AFC op %d", op)
						return
					}
					if _, err = server.Write(afcReply(seq, responseOp, reply)); err != nil {
						done <- nil
						return
					}
					if op == 24 {
						done <- nil
						return
					}
				}
			}()
			source := []byte("private setup envelope")
			total := int64(len(source))
			if kind == "short source" {
				source = source[:3]
			}
			err := writeBootstrapDocument(ctx, client, "org.ipaloader.ios.ABCDE12345", "IPALoaderBootstrap.json", bytes.NewReader(source), total, func(int64, int64) {
				if kind == "cancelled" {
					cancel()
				}
			})
			client.Close()
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if (err == nil) != (kind == "complete") {
				t.Fatalf("unexpected result: %v", err)
			}
			if committed != (kind == "complete") {
				t.Fatal("unverified bootstrap became visible")
			}
		})
	}
}
func TestBootstrapRejectsUnownedPathsBeforeConnecting(t *testing.T) {
	for _, name := range []string{"../secret", "other.json", "/IPALoader.ipa"} {
		if err := WriteBootstrapDocument(context.Background(), "device", "org.ipaloader.ios.ABCDE12345", name, bytes.NewReader([]byte("x")), 1, nil); err == nil {
			t.Fatal("accepted arbitrary document write")
		}
	}
}

func TestBootstrapCannotTargetAnotherApp(t *testing.T) {
	if err := WriteBootstrapDocument(context.Background(), "device", "org.example.other", "IPALoaderBootstrap.json", bytes.NewReader([]byte("x")), 1, nil); err == nil {
		t.Fatal("accepted a non-loader app destination")
	}
}
