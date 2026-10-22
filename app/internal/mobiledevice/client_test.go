package mobiledevice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

type memoryWire struct {
	files        map[string][]byte
	offsets      map[uint64]int
	paths        map[uint64]string
	next         uint64
	upgrades     int
	chunk        int
	zeroWrite    bool
	upgradeError error
	writeError   error
	failAfter    int
}

func memoryClient() (*Client, *memoryWire) {
	w := &memoryWire{files: map[string][]byte{}, offsets: map[uint64]int{}, paths: map[uint64]string{}, chunk: 7000}
	return &Client{wire: w, uploaded: map[string]int64{}}, w
}
func (w *memoryWire) mkdir(string) error       { return nil }
func (w *memoryWire) remove(path string) error { delete(w.files, path); return nil }
func (w *memoryWire) size(path string) (uint64, error) {
	b, ok := w.files[path]
	if !ok {
		return 0, &Error{Code: 8}
	}
	return uint64(len(b)), nil
}
func (w *memoryWire) open(path string, mode int) (uint64, error) {
	if mode == 3 {
		w.files[path] = nil
	} else if _, ok := w.files[path]; !ok {
		return 0, &Error{Code: 8}
	}
	w.next++
	w.paths[w.next] = path
	return w.next, nil
}
func (w *memoryWire) closeFile(uint64) error { return nil }
func (w *memoryWire) write(handle uint64, b []byte) (int, error) {
	if w.writeError != nil && len(w.files[w.paths[handle]]) >= w.failAfter {
		return len(b), w.writeError
	}
	if w.zeroWrite {
		return 0, nil
	}
	n := len(b)
	if n > w.chunk {
		n = w.chunk
	}
	path := w.paths[handle]
	w.files[path] = append(w.files[path], b[:n]...)
	return n, nil
}

func TestFailedWriteCountDoesNotAdvanceAcknowledgedProgress(t *testing.T) {
	c, w := memoryClient()
	defer c.Close()
	w.chunk = 64 << 10
	w.failAfter = 64 << 10
	w.writeError = errors.New("device response lost")
	ctx := context.Background()
	stage, err := c.NewStage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := stage + "/fixture.ipa"
	body := bytes.Repeat([]byte{1}, 2<<16)
	var progress int64
	sent, err := c.Upload(ctx, path, bytes.NewReader(body), int64(len(body)), func(n, _ int64) { progress = n })
	if !errors.Is(err, w.writeError) || sent != 64<<10 || progress != sent || int64(len(w.files[path])) != sent {
		t.Fatal("failed-write bytes were reported as acknowledged")
	}
	if submitted, err := c.Upgrade(ctx, path, int64(len(body))); err == nil || submitted || w.upgrades != 0 {
		t.Fatal("failed upload could be submitted")
	}
}
func (w *memoryWire) read(handle uint64, b []byte) (int, error) {
	path := w.paths[handle]
	n := copy(b, w.files[path][w.offsets[handle]:])
	w.offsets[handle] += n
	return n, nil
}
func (w *memoryWire) upgrade(_ context.Context, _ string, progress func(InstallProgress)) (bool, error) {
	w.upgrades++
	if progress != nil {
		progress(InstallProgress{Submitted: true, Percent: -1})
	}
	return true, w.upgradeError
}
func (w *memoryWire) close() {}

func TestShortWritesDigestAndConfirmedUploadBeforeUpgrade(t *testing.T) {
	c, w := memoryClient()
	ctx := context.Background()
	defer c.Close()
	stage, err := c.NewStage(ctx)
	if err != nil || !validPath(stage) {
		t.Fatal("owned staging namespace missing")
	}
	path := stage + "/package.ipa"
	body := bytes.Repeat([]byte("owned fixture bytes"), 20000)
	previous := int64(0)
	n, err := c.Upload(ctx, path, bytes.NewReader(body), int64(len(body)), func(sent, total int64) {
		if sent <= previous || total != int64(len(body)) {
			t.Fatal("acknowledged progress is not monotonic")
		}
		previous = sent
	})
	if err != nil || n != int64(len(body)) || !bytes.Equal(w.files[path], body) {
		t.Fatal("short writes lost source bytes")
	}
	digest, size, err := c.Digest(ctx, path)
	expected := sha256.Sum256(body)
	if err != nil || size != n || digest != hex.EncodeToString(expected[:]) {
		t.Fatal("remote verification disagrees")
	}
	submitted, err := c.Upgrade(ctx, path, n)
	if err != nil || !submitted || w.upgrades != 1 {
		t.Fatal("verified full upload did not reach installer")
	}
}

func TestCancellationRetainsExactPartialAndPreventsInstallation(t *testing.T) {
	c, w := memoryClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close()
	stage, _ := c.NewStage(ctx)
	path := stage + "/partial.ipa"
	body := bytes.Repeat([]byte{42}, 200000)
	sent, err := c.Upload(ctx, path, bytes.NewReader(body), int64(len(body)), func(n, _ int64) {
		if n >= 20000 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || sent <= 0 || sent >= int64(len(body)) || int64(len(w.files[path])) != sent {
		t.Fatal("cancelled upload byte count is not authoritative")
	}
	submitted, err := c.Upgrade(context.Background(), path, int64(len(body)))
	if err == nil || submitted || w.upgrades != 0 {
		t.Fatal("partial upload reached installer")
	}
	// Retry under a fresh operation context, without inventing the remainder.
	sent, err = c.Upload(context.Background(), path, bytes.NewReader(body), int64(len(body)), nil)
	if err != nil || sent != int64(len(body)) || !bytes.Equal(w.files[path], body) {
		t.Fatal("retry appended to partial or lost source data")
	}
}

func TestUncertainUpgradeAndChangedStagedFile(t *testing.T) {
	c, w := memoryClient()
	defer c.Close()
	ctx := context.Background()
	stage, _ := c.NewStage(ctx)
	path := stage + "/package.ipa"
	c.Upload(ctx, path, bytes.NewReader([]byte("fixture")), 7, nil)
	w.files[path] = []byte("short")
	if submitted, err := c.Upgrade(ctx, path, 7); err == nil || submitted || w.upgrades != 0 {
		t.Fatal("changed staged file reached installer")
	}
	c.Upload(ctx, path, bytes.NewReader([]byte("fixture")), 7, nil)
	w.upgradeError = errors.New("connection lost after submission")
	if submitted, err := c.Upgrade(ctx, path, 7); err == nil || !submitted {
		t.Fatal("uncertain submission incorrectly reported as not sent")
	}
	if _, err := c.Upload(ctx, path, nil, 7, nil); err == nil {
		t.Fatal("invalid source accepted")
	}
	before := w.upgrades
	if submitted, err := c.Upgrade(ctx, path, 7); err == nil || submitted || w.upgrades != before {
		t.Fatal("failed new upload reused an old completion marker")
	}
}

func TestStagingBoundaryAndBrokenSources(t *testing.T) {
	c, w := memoryClient()
	defer c.Close()
	ctx := context.Background()
	for _, path := range []string{"PublicStaging", "Documents/personal.ipa", "PublicStaging/IPALoader-123/other.ipa", "PublicStaging/IPALoader-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/../personal.ipa"} {
		if c.Remove(ctx, path) == nil {
			t.Fatal("cleanup escaped owned staging namespace")
		}
	}
	stage, _ := c.NewStage(ctx)
	path := stage + "/package.ipa"
	if _, err := c.Upload(ctx, path, bytes.NewReader([]byte("short")), 100, nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("short source was treated as complete")
	}
	w.zeroWrite = true
	if _, err := c.Upload(ctx, path, bytes.NewReader([]byte("fixture")), 7, nil); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal("stalled transport did not stop")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	before := w.next
	if _, err := c.Upload(cancelled, path, bytes.NewReader(nil), 1, nil); !errors.Is(err, context.Canceled) || w.next != before {
		t.Fatal("pre-cancelled upload touched device")
	}
	c.Close()
	if _, err := c.Size(ctx, path); !errors.Is(err, ErrClosed) {
		t.Fatal("closed client still accessible")
	}
}
