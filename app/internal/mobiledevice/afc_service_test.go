//go:build windows || linux || darwin

package mobiledevice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func afcReply(seq, op uint64, body []byte) []byte {
	packet := make([]byte, 40+len(body))
	copy(packet, "CFA6LPAA")
	binary.LittleEndian.PutUint64(packet[8:], uint64(len(packet)))
	binary.LittleEndian.PutUint64(packet[16:], uint64(len(packet)))
	binary.LittleEndian.PutUint64(packet[24:], seq)
	binary.LittleEndian.PutUint64(packet[32:], op)
	copy(packet[40:], body)
	return packet
}
func readAFCRequest(conn net.Conn) (uint64, uint64, []byte, error) {
	var header [40]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, 0, nil, err
	}
	size := binary.LittleEndian.Uint64(header[8:])
	if size < 40 || size > 1<<20 {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, int(size)-40)
	_, err := io.ReadFull(conn, body)
	return binary.LittleEndian.Uint64(header[24:]), binary.LittleEndian.Uint64(header[32:]), body, err
}
func TestWindowsAFCAcknowledgesOnlyCompletedWrite(t *testing.T) {
	for _, test := range []struct {
		name string
		code uint64
		drop bool
		want int
	}{{"success", 0, false, 7}, {"device-error", 20, false, 0}, {"lost-ack", 0, true, 0}} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				defer server.Close()
				seq, _, _, err := readAFCRequest(server)
				if err != nil {
					return
				}
				if test.drop {
					return
				}
				packet := afcReply(seq, 1, afcNumber(test.code))
				for _, b := range packet {
					if _, err := server.Write([]byte{b}); err != nil {
						return
					}
				}
			}()
			w := &windowsAFC{conn: client, ctx: context.Background()}
			n, err := w.write(1, []byte("payload"))
			if n != test.want {
				t.Fatalf("Acknowledged %d bytes, expected %d", n, test.want)
			}
			if test.want == 0 && err == nil {
				t.Fatal("Unacknowledged write returned success")
			}
			if test.want > 0 && err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestWindowsAFCRejectsWrongSequenceAndOversize(t *testing.T) {
	for _, bad := range []string{"sequence", "size", "magic"} {
		t.Run(bad, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				defer server.Close()
				seq, _, _, err := readAFCRequest(server)
				if err != nil {
					return
				}
				packet := afcReply(seq, 1, afcNumber(0))
				switch bad {
				case "sequence":
					binary.LittleEndian.PutUint64(packet[24:], seq+1)
				case "size":
					binary.LittleEndian.PutUint64(packet[8:], 1<<20+1)
				case "magic":
					packet[0] = 'X'
				}
				_, _ = server.Write(packet[:40])
			}()
			w := &windowsAFC{conn: client, ctx: context.Background()}
			if _, _, err := w.exchange(9, []byte("unused\x00"), nil); err == nil {
				t.Fatal("Accepted malformed AFC response")
			}
			if w.conn != nil {
				t.Fatal("Malformed response did not poison AFC stream")
			}
		})
	}
}
func TestWindowsAFCBlockedCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	w := &windowsAFC{conn: client, ctx: ctx}
	done := make(chan error, 1)
	go func() { _, _, err := w.exchange(9, []byte("unused\x00"), nil); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Unexpected cancellation error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Blocked AFC cancellation did not finish")
	}
}
func TestWindowsInstallServiceDelayedCompletion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		defer server.Close()
		_, err := readDevicePlist(server)
		if err != nil {
			return
		}
		time.Sleep(350 * time.Millisecond)
		_ = sendDevicePlist(server, map[string]any{"Status": "Complete"})
	}()
	submitted, err := runUpgrade(ctx, &windowsInstallService{conn: client, ctx: ctx}, "PublicStaging/IPALoader-"+strings.Repeat("a", 32)+"/application.ipa")
	if err != nil || !submitted {
		t.Fatalf("Delayed installation completion failed: submitted=%t err=%v", submitted, err)
	}
}
func TestWindowsSelectedOwnedAFCTransfer(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_WINDOWS_AFC") != "1" {
		t.Skip("explicit owned synthetic staging transfer, no installation")
	}
	checkSelectedOwnedAFCTransfer(t)
}

func checkSelectedOwnedAFCTransfer(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fox := selectedWindowsTestDevice(t, ctx)
	transport := "usb"
	if fox.Transport == "Network" {
		transport = "wifi"
	}
	t.Logf("Owned staging transfer route: %s", fox.Transport)
	c, err := Open(ctx, Options{UDID: fox.UDID, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stage, err := c.NewStage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := stage + "/application.ipa"
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := c.Remove(cleanup, path); err != nil {
			t.Error("Owned staged file cleanup failed:", err)
		}
		if err := c.Remove(cleanup, stage); err != nil {
			t.Error("Owned staging directory cleanup failed:", err)
		}
	}()
	payload := bytes.Repeat([]byte("Windows AFC synthetic staging fixture\n"), 8192)
	partial, stop := context.WithCancel(ctx)
	sent, err := c.Upload(partial, path, bytes.NewReader(payload), int64(len(payload)), func(n, total int64) {
		if n >= 64<<10 {
			stop()
		}
	})
	if err != context.Canceled || sent == 0 || sent >= int64(len(payload)) {
		t.Fatalf("Partial upload did not cancel after acknowledgements: sent=%d err=%v", sent, err)
	}
	partialSent := sent
	remote, err := c.Size(ctx, path)
	if err != nil || remote != uint64(sent) {
		t.Fatalf("Remote partial size differed from acknowledgements: remote=%d sent=%d err=%v", remote, sent, err)
	}
	sent, err = c.Upload(ctx, path, bytes.NewReader(payload), int64(len(payload)), nil)
	if err != nil || sent != int64(len(payload)) {
		t.Fatal("Full staging retry failed:", err)
	}
	remote, err = c.Size(ctx, path)
	if err != nil || remote != uint64(len(payload)) {
		t.Fatal("Full staged size verification failed:", err)
	}
	digest, count, err := c.Digest(ctx, path)
	expected := sha256.Sum256(payload)
	if err != nil || count != int64(len(payload)) || digest != hex.EncodeToString(expected[:]) {
		t.Fatal("Independent staged content digest mismatch:", err)
	}
	t.Logf("Partial cancellation/retry verified: %d acknowledged partial bytes; %d complete bytes; SHA-256 matched; no install submitted", partialSent, count)
}
