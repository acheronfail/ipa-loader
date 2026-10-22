// Package mobiledevice provides a bounded, cancellable IPA staging path using
// the local usbmuxd device service.
// Loading this package never installs dependencies or changes pairing.
package mobiledevice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

var ErrUnavailable = errors.New("device service is unavailable")
var ErrClosed = errors.New("device transport is closed")

type Options struct {
	UDID, Transport string
}

func (Options) String() string   { return "Private iPhone transport configuration" }
func (Options) GoString() string { return "Private iPhone transport configuration" }

type Error struct {
	Operation string
	Code      int
}
type InstallProgress struct {
	Submitted bool
	Percent   int
}

func (e *Error) Error() string { return fmt.Sprintf("Device %s failed (code %d)", e.Operation, e.Code) }

type wire interface {
	mkdir(string) error
	remove(string) error
	size(string) (uint64, error)
	open(string, int) (uint64, error)
	closeFile(uint64) error
	write(uint64, []byte) (int, error)
	read(uint64, []byte) (int, error)
	upgrade(context.Context, string, func(InstallProgress)) (bool, error)
	close()
}

type Client struct {
	mu       sync.Mutex
	wire     wire
	closed   bool
	uploaded map[string]int64
}

func (*Client) String() string   { return "Private iPhone transport" }
func (*Client) GoString() string { return "Private iPhone transport" }

func Open(ctx context.Context, options Options) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Transport != "usb" && options.Transport != "wifi" {
		return nil, errors.New("Select USB or Wi-Fi transport")
	}
	if options.UDID == "" || len(options.UDID) > 256 || strings.ContainsAny(options.UDID, "\x00\r\n") {
		return nil, errors.New("Invalid iPhone hardware identifier")
	}
	w, err := openConfiguredNative(ctx, options)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		w.close()
		return nil, err
	}
	return &Client{wire: w, uploaded: map[string]int64{}}, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.wire.close()
	}
}
func (c *Client) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closed {
		return ErrClosed
	}
	if contextual, ok := c.wire.(interface{ setContext(context.Context) }); ok {
		contextual.setContext(ctx)
	}
	return nil
}
func isCode(err error, code int) bool {
	var native *Error
	return errors.As(err, &native) && native.Code == code
}

var ownedPath = regexp.MustCompile(`^PublicStaging/IPALoader-[a-f0-9]{32}(?:/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127})?$`)

func validPath(path string) bool { return ownedPath.MatchString(path) }

func (c *Client) NewStage(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return "", err
	}
	if err := c.wire.mkdir("PublicStaging"); err != nil && !isCode(err, 16) {
		return "", err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	path := "PublicStaging/IPALoader-" + hex.EncodeToString(random[:])
	if err := c.wire.mkdir(path); err != nil {
		return "", err
	}
	return path, nil
}

func (c *Client) Size(ctx context.Context, path string) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return 0, err
	}
	if !validPath(path) {
		return 0, errors.New("Only task-owned staging paths are accessible")
	}
	return c.wire.size(path)
}

func (c *Client) Remove(ctx context.Context, path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return err
	}
	if !validPath(path) {
		return errors.New("Only task-owned staging paths can be removed")
	}
	delete(c.uploaded, path)
	err := c.wire.remove(path)
	if isCode(err, 8) {
		return nil
	}
	return err
}

// Upload checks cancellation between acknowledged chunks. A callback may cancel
// ctx, but must not call other methods on this Client. Native calls finish under
// their library timeouts; cancellation never implies rollback on the phone.
func (c *Client) Upload(ctx context.Context, path string, source io.Reader, total int64, progress func(int64, int64)) (sent int64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A new attempt invalidates any prior completion marker, even when this
	// attempt is cancelled or malformed before touching the phone.
	if validPath(path) {
		delete(c.uploaded, path)
	}
	if err = c.ready(ctx); err != nil {
		return
	}
	if !validPath(path) || !strings.HasSuffix(path, ".ipa") || total <= 0 || source == nil {
		return 0, errors.New("Expected a nonempty IPA in a task-owned staging path")
	}
	handle, err := c.wire.open(path, 3)
	if err != nil {
		return 0, err
	}
	defer func() {
		closeErr := c.wire.closeFile(handle)
		if err == nil {
			err = closeErr
		}
		if err == nil {
			c.uploaded[path] = sent
		}
	}()
	buffer := make([]byte, 64<<10)
	for sent < total {
		if err = ctx.Err(); err != nil {
			return
		}
		want := int64(len(buffer))
		if total-sent < want {
			want = total - sent
		}
		var n int
		n, err = io.ReadFull(source, buffer[:want])
		if err != nil {
			return
		}
		for offset := 0; offset < n; {
			if err = ctx.Err(); err != nil {
				return
			}
			var written int
			written, err = c.wire.write(handle, buffer[offset:n])
			// A failed AFC write may report bytes sent before its response was
			// lost. Those bytes are not acknowledged and must not advance UI
			// progress or the count returned to recovery callers.
			if err != nil {
				return
			}
			if written < 0 || written > n-offset {
				return sent, errors.New("Device returned an invalid upload byte count")
			}
			sent += int64(written)
			offset += written
			if progress != nil && written > 0 {
				progress(sent, total)
			}
			if written == 0 {
				return sent, io.ErrNoProgress
			}
		}
	}
	err = ctx.Err()
	return
}

func (c *Client) Digest(ctx context.Context, path string) (digest string, count int64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.ready(ctx); err != nil {
		return
	}
	if !validPath(path) {
		return "", 0, errors.New("Only task-owned staging paths are accessible")
	}
	handle, err := c.wire.open(path, 1)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		closeErr := c.wire.closeFile(handle)
		if err == nil {
			err = closeErr
		}
	}()
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return
		}
		var n int
		n, err = c.wire.read(handle, buffer)
		if n < 0 || n > len(buffer) {
			return "", count, errors.New("Device returned an invalid download byte count")
		}
		hash.Write(buffer[:n])
		count += int64(n)
		if err != nil {
			return
		}
		if n == 0 {
			return hex.EncodeToString(hash.Sum(nil)), count, nil
		}
	}
}

// Upgrade is permitted only after this Client completed the full upload and
// the phone confirms its size. A true submitted result remains true on an
// uncertain failure; caller must independently confirm installation/runtime.
// Progress callbacks may cancel ctx, but must not re-enter this Client.
func (c *Client) Upgrade(ctx context.Context, path string, total int64, progress ...func(InstallProgress)) (submitted bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.ready(ctx); err != nil {
		return
	}
	if !validPath(path) || total <= 0 || c.uploaded[path] != total {
		return false, errors.New("IPA upload is incomplete; installation was not submitted")
	}
	size, err := c.wire.size(path)
	if err != nil {
		return false, err
	}
	if size != uint64(total) {
		return false, errors.New("Staged IPA size changed; installation was not submitted")
	}
	if err = ctx.Err(); err != nil {
		return
	}
	notify := func(event InstallProgress) {
		for _, callback := range progress {
			if callback != nil {
				callback(event)
			}
		}
	}
	submitted, err = c.wire.upgrade(ctx, path, notify)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return
}
