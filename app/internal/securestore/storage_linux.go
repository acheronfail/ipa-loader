//go:build linux

package securestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os/exec"
	"path/filepath"
	"time"
)

// Linux secrets are kept in the desktop Secret Service. There is no on-disk
// plaintext fallback. Paths identify records, rather than containing secrets.
const maxBlob = 2 << 20

func recordKey(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("Secure storage requires an absolute record path")
	}
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:]), nil
}

// A bounded sink prevents an unexpected helper response from allocating without
// limit. Helpers never write secret data to application diagnostics.
type limitedOutput struct {
	bytes.Buffer
	limit int
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("Secret Service response exceeds its size limit")
	}
	return b.Buffer.Write(p)
}

var secretCommand = func(ctx context.Context, input []byte, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, "secret-tool", args...)
	command.Stdin = bytes.NewReader(input)
	output := &limitedOutput{limit: 4 << 20}
	diagnostic := &limitedOutput{limit: 8192}
	command.Stdout, command.Stderr = output, diagnostic
	err := command.Run()
	return output.Bytes(), diagnostic.Bytes(), err
}

func Read(path string, limit int) ([]byte, error) {
	key, err := recordKey(path)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxBlob {
		return nil, errors.New("Invalid secure storage size limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, diagnostic, err := secretCommand(ctx, nil, "lookup", "application", "org.example.ipaloader", "record", key)
	defer clear(data)
	if err != nil {
		var exit *exec.ExitError
		// secret-tool returns 1 without diagnostics when no matching item exists.
		if errors.As(err, &exit) && exit.ExitCode() == 1 && len(diagnostic) == 0 && ctx.Err() == nil {
			return nil, nil
		}
		return nil, errors.New("Could not read desktop Secret Service; install secret-tool and unlock your keyring")
	}
	data = bytes.TrimSpace(data)
	if len(data) > base64.StdEncoding.EncodedLen(limit) {
		return nil, errors.New("Secure storage exceeds its size limit")
	}
	plain, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(plain) > limit {
		clear(plain)
		return nil, errors.New("Invalid desktop Secret Service record")
	}
	return plain, nil
}

func Write(path string, data []byte) error {
	key, err := recordKey(path)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxBlob {
		return errors.New("Invalid secure storage data")
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	defer clear(encoded)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _, err = secretCommand(ctx, encoded, "store", "--label=IPA Loader", "application", "org.example.ipaloader", "record", key)
	if err != nil {
		return errors.New("Could not save in desktop Secret Service; install secret-tool and unlock your keyring")
	}
	return nil
}
