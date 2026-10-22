//go:build windows || linux || darwin

package mobiledevice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func openConfiguredNative(ctx context.Context, options Options) (wire, error) {
	s, err := windowsSessionForTransport(ctx, options.UDID, options.Transport)
	if err != nil {
		return nil, err
	}
	defer s.close()
	conn, err := s.service(ctx, "com.apple.afc")
	if err != nil {
		return nil, err
	}
	return &windowsAFC{conn: conn, ctx: ctx, udid: options.UDID, transport: options.Transport}, nil
}

type windowsAFC struct {
	conn            net.Conn
	ctx             context.Context
	udid, transport string
	sequence        uint64
}

func (w *windowsAFC) setContext(ctx context.Context) { w.ctx = ctx }
func (w *windowsAFC) close() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

// AFC has a 40-byte little-endian header, a command-specific inline body,
// and an optional payload. Writes count only after the corresponding status
// packet acknowledges them. Any broken exchange poisons the stream.
func (w *windowsAFC) exchange(operation uint64, inline, payload []byte) (uint64, []byte, error) {
	if w.conn == nil {
		return 0, nil, ErrClosed
	}
	if err := w.ctx.Err(); err != nil {
		return 0, nil, err
	}
	w.sequence++
	packet := make([]byte, 40+len(inline)+len(payload))
	copy(packet, "CFA6LPAA")
	binary.LittleEndian.PutUint64(packet[8:], uint64(len(packet)))
	binary.LittleEndian.PutUint64(packet[16:], uint64(40+len(inline)))
	binary.LittleEndian.PutUint64(packet[24:], w.sequence)
	binary.LittleEndian.PutUint64(packet[32:], operation)
	copy(packet[40:], inline)
	copy(packet[40+len(inline):], payload)
	stop := watchConnection(w.ctx, w.conn)
	defer stop()
	fail := func(err error) (uint64, []byte, error) { w.close(); return 0, nil, err }
	if err := writeAll(w.conn, packet); err != nil {
		return fail(deviceIOError(w.ctx))
	}
	var header [40]byte
	if _, err := io.ReadFull(w.conn, header[:]); err != nil {
		return fail(deviceIOError(w.ctx))
	}
	total := binary.LittleEndian.Uint64(header[8:])
	part := binary.LittleEndian.Uint64(header[16:])
	seq := binary.LittleEndian.Uint64(header[24:])
	op := binary.LittleEndian.Uint64(header[32:])
	if string(header[:8]) != "CFA6LPAA" || total < 40 || total > 1<<20 || part < 40 || part > total || seq != w.sequence {
		return fail(errors.New("Invalid AFC response header"))
	}
	body := make([]byte, int(total)-40)
	if _, err := io.ReadFull(w.conn, body); err != nil {
		return fail(deviceIOError(w.ctx))
	}
	if op == 1 {
		if len(body) != 8 {
			return fail(errors.New("Invalid AFC status response"))
		}
		code := binary.LittleEndian.Uint64(body)
		if code > 0x7fffffff {
			return fail(errors.New("Invalid AFC status code"))
		}
		if code != 0 {
			return op, nil, &Error{Operation: "staging operation", Code: int(code)}
		}
	}
	return op, body, nil
}
func (w *windowsAFC) status(operation uint64, inline, payload []byte) error {
	op, _, err := w.exchange(operation, inline, payload)
	if err != nil {
		return err
	}
	if op != 1 {
		w.close()
		return errors.New("AFC did not acknowledge the staging operation")
	}
	return nil
}
func (w *windowsAFC) mkdir(path string) error  { return w.status(9, append([]byte(path), 0), nil) }
func (w *windowsAFC) remove(path string) error { return w.status(8, append([]byte(path), 0), nil) }
func (w *windowsAFC) size(path string) (uint64, error) {
	op, body, err := w.exchange(10, append([]byte(path), 0), nil)
	if err != nil {
		return 0, err
	}
	if op != 2 || len(body) == 0 || body[len(body)-1] != 0 {
		return 0, errors.New("Invalid AFC file information")
	}
	fields := strings.Split(string(body[:len(body)-1]), "\x00")
	if len(fields)%2 != 0 {
		return 0, errors.New("Invalid AFC file information")
	}
	for i := 0; i < len(fields); i += 2 {
		if fields[i] == "st_size" {
			n, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return 0, errors.New("Invalid AFC file size")
			}
			return n, nil
		}
	}
	return 0, errors.New("AFC did not report the staged file size")
}
func (w *windowsAFC) open(path string, mode int) (uint64, error) {
	data := make([]byte, 8+len(path)+1)
	binary.LittleEndian.PutUint64(data, uint64(mode))
	copy(data[8:], path)
	op, body, err := w.exchange(13, data, nil)
	if err != nil {
		return 0, err
	}
	if op != 14 || len(body) != 8 {
		return 0, errors.New("Invalid AFC open response")
	}
	handle := binary.LittleEndian.Uint64(body)
	if handle == 0 {
		return 0, errors.New("Invalid AFC file handle")
	}
	return handle, nil
}
func afcNumber(n uint64) []byte { p := make([]byte, 8); binary.LittleEndian.PutUint64(p, n); return p }
func (w *windowsAFC) closeFile(handle uint64) error {
	// If cancellation happened between complete exchanges, release the handle
	// with a short independent cleanup timeout. A poisoned stream stays closed.
	previous := w.ctx
	if previous.Err() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.ctx = ctx
		defer func() { w.ctx = previous }()
	}
	return w.status(20, afcNumber(handle), nil)
}
func (w *windowsAFC) write(handle uint64, data []byte) (int, error) {
	if len(data) > 64<<10 {
		return 0, errors.New("AFC upload chunk exceeds the protocol limit")
	}
	if err := w.status(16, afcNumber(handle), data); err != nil {
		return 0, err
	}
	return len(data), nil
}
func (w *windowsAFC) read(handle uint64, data []byte) (int, error) {
	inline := append(afcNumber(handle), afcNumber(uint64(len(data)))...)
	op, body, err := w.exchange(15, inline, nil)
	if isCode(err, 14) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if op == 1 {
		return 0, nil
	}
	if op != 2 || len(body) > len(data) {
		w.close()
		return 0, errors.New("Invalid AFC read response")
	}
	return copy(data, body), nil
}
func (w *windowsAFC) upgrade(ctx context.Context, path string, progress func(InstallProgress)) (bool, error) {
	session, err := windowsSessionForTransport(ctx, w.udid, w.transport)
	if err != nil {
		return false, err
	}
	defer session.close()
	conn, err := session.service(ctx, "com.apple.mobile.installation_proxy")
	if err != nil {
		return false, err
	}
	service := &windowsInstallService{conn: conn, ctx: ctx}
	// Cancellation closes the whole observation connection, including TLS, so a
	// blocked read cannot hang. It does not promise installation rollback.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	return runUpgrade(ctx, service, path, progress)
}

type windowsInstallService struct {
	conn net.Conn
	ctx  context.Context
}

func (s *windowsInstallService) close() { _ = s.conn.Close() }
func (s *windowsInstallService) send(data []byte) (int, error) {
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := s.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.conn.SetWriteDeadline(deadline)
	n, err := s.conn.Write(data)
	if s.ctx.Err() != nil {
		return n, s.ctx.Err()
	}
	return n, err
}
func (s *windowsInstallService) receive(data []byte, timeout uint32) (int, error) {
	deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
	if d, ok := s.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.conn.SetReadDeadline(deadline)
	n, err := s.conn.Read(data)
	if s.ctx.Err() != nil {
		return n, s.ctx.Err()
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return n, errReceiveTimeout
	}
	return n, err
}
