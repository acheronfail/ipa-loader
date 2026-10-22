//go:build windows || linux || darwin

package mobiledevice

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"ipa-loader/app/internal/bootstrap"
	"net"
)

// WriteBootstrapDocument exposes only the two bootstrap files in the selected
// loader's Documents directory. Data is streamed and read back before rename.
func WriteBootstrapDocument(ctx context.Context, udid, bundleID, filename string, source io.Reader, total int64, progress func(int64, int64)) error {
	if filename != "IPALoaderBootstrap.json" && filename != "IPALoader.ipa" {
		return errors.New("Unsupported bootstrap filename")
	}
	if !bootstrap.IsLoaderBundleID(bundleID) || len(bundleID) > 255 || source == nil || total <= 0 {
		return errors.New("Invalid bootstrap destination")
	}
	s, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return err
	}
	defer s.close()
	conn, err := s.service(ctx, "com.apple.mobile.house_arrest")
	if err != nil {
		return err
	}
	defer conn.Close()
	return writeBootstrapDocument(ctx, conn, bundleID, filename, source, total, progress)
}
func writeBootstrapDocument(ctx context.Context, conn net.Conn, bundleID, filename string, source io.Reader, total int64, progress func(int64, int64)) error {
	if filename != "IPALoaderBootstrap.json" && filename != "IPALoader.ipa" {
		return errors.New("Unsupported bootstrap filename")
	}
	if total <= 0 || source == nil || !bootstrap.IsLoaderBundleID(bundleID) {
		return errors.New("Invalid bootstrap transfer")
	}
	r, err := deviceExchange(ctx, conn, map[string]any{"Command": "VendDocuments", "Identifier": bundleID})
	if err != nil {
		return err
	}
	if r["Status"] != "Complete" {
		return errors.New("Device did not grant IPA Loader document access")
	}
	w := &windowsAFC{ctx: ctx, conn: conn}
	defer w.close()
	if err = checkDocumentPath(w, "Documents"); err != nil {
		return err
	}
	dest := "Documents/" + filename
	tmp := dest + ".incoming"
	// Never follow an existing entry. Remove only this reserved staging filename.
	if err = w.remove(tmp); err != nil && !isCode(err, 8) {
		return err
	}
	h, err := w.open(tmp, 3)
	if err != nil {
		return err
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var sent int64
	for sent < total {
		if err = ctx.Err(); err != nil {
			break
		}
		n := int64(len(buffer))
		if total-sent < n {
			n = total - sent
		}
		var count int
		count, err = io.ReadFull(source, buffer[:n])
		if err != nil {
			break
		}
		hash.Write(buffer[:count])
		var acknowledged int
		acknowledged, err = w.write(h, buffer[:count])
		if err != nil {
			break
		}
		if acknowledged != count {
			err = io.ErrShortWrite
			break
		}
		sent += int64(count)
		if progress != nil {
			progress(sent, total)
		}
	}
	closeErr := w.closeFile(h)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	size, err := w.size(tmp)
	if err != nil {
		return err
	}
	if size != uint64(total) {
		return errors.New("Bootstrap transfer size mismatch")
	}
	h, err = w.open(tmp, 1)
	if err != nil {
		return err
	}
	verify := sha256.New()
	var read int64
	for {
		n, e := w.read(h, buffer)
		if e != nil {
			w.closeFile(h)
			return e
		}
		if n == 0 {
			break
		}
		read += int64(n)
		if read > total {
			w.closeFile(h)
			return errors.New("Bootstrap verification exceeded expected size")
		}
		verify.Write(buffer[:n])
	}
	if err = w.closeFile(h); err != nil {
		return err
	}
	if read != total || string(hash.Sum(nil)) != string(verify.Sum(nil)) {
		return errors.New("Bootstrap transfer verification failed")
	}
	// AFC rename replaces the final regular file atomically; config is committed last.
	return w.status(24, append(append(append([]byte(tmp), 0), []byte(dest)...), 0), nil)
}
