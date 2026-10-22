package codesignverify

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	archive, err := zip.OpenReader(filepath.Join("..", "..", "..", "fixtures", "ipas", "ipa-loader-sharing-v12-adhoc.ipa"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	work := t.TempDir()
	for _, member := range archive.File {
		filename, err := safeResource(work, strings.TrimSuffix(member.Name, "/"))
		if err != nil {
			t.Fatal(err)
		}
		if member.FileInfo().IsDir() {
			if err = os.MkdirAll(filename, 0700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		input, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filename, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(work, "Payload", "SharingTest.app")
}

func TestCommittedAdHocBundleIntegrity(t *testing.T) {
	bundle := fixture(t)
	report, err := VerifyBundle(context.Background(), bundle, Options{AllowAdHoc: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Images) != 2 || report.ResourceHashes < 4 {
		t.Fatal("host and extension were not verified")
	}
	for _, image := range report.Images {
		if image.CMSVerified || image.Slices != 1 || len(image.CDHashes) == 0 {
			t.Fatal("ad-hoc evidence incorrectly described")
		}
	}
	if _, err = VerifyBundle(context.Background(), bundle, Options{}); err == nil {
		t.Fatal("ad-hoc input accepted as developer signed")
	}
	if _, err = VerifyBundle(context.Background(), bundle, Options{AllowAdHoc: true, RequireNoEntitlements: true}); err == nil {
		t.Fatal("app entitlements accepted on a library signing object")
	}
}

func TestCommittedBundleTamperingAndUnsealedAdditions(t *testing.T) {
	for _, kind := range []string{"host page", "extension page", "info", "resource manifest", "unsealed file", "unsealed nested file", "identifier", "entitlements"} {
		t.Run(kind, func(t *testing.T) {
			bundle := fixture(t)
			options := Options{AllowAdHoc: true}
			switch kind {
			case "host page", "extension page":
				filename := filepath.Join(bundle, "SharingTest")
				if kind == "extension page" {
					filename = filepath.Join(bundle, "PlugIns", "SharingShare.appex", "SharingShare")
				}
				body, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				_, limit, err := signature(body)
				if err != nil {
					t.Fatal(err)
				}
				body[limit-1] ^= 1
				if err = os.WriteFile(filename, body, 0600); err != nil {
					t.Fatal(err)
				}
			case "info", "resource manifest":
				filename := filepath.Join(bundle, "Info.plist")
				if kind == "resource manifest" {
					filename = filepath.Join(bundle, "_CodeSignature", "CodeResources")
				}
				file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteString(" ")
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "unsealed file", "unsealed nested file":
				filename := filepath.Join(bundle, "added.txt")
				if kind == "unsealed nested file" {
					filename = filepath.Join(bundle, "PlugIns", "SharingShare.appex", "added.txt")
				}
				if err := os.WriteFile(filename, []byte("unsealed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "identifier":
				options.Identifier = "org.example.wrong"
			case "entitlements":
				options.Entitlements = []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>wrong</key><true/></dict></plist>`)
			}
			if _, err := VerifyBundle(context.Background(), bundle, options); err == nil {
				t.Fatal("tampered bundle accepted")
			}
		})
	}
}

func TestMalformedContainersFailWithoutPanics(t *testing.T) {
	for n := 0; n < 128; n++ {
		data := make([]byte, n)
		if _, _, err := signature(data); err == nil {
			t.Fatal("zero-filled Mach-O accepted")
		}
		if _, err := slices(data); n < 8 && err == nil {
			t.Fatal("truncated input accepted")
		}
	}
	if _, err := safeResource(t.TempDir(), "../outside"); err == nil {
		t.Fatal("resource escape accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyBundle(ctx, fixture(t), Options{AllowAdHoc: true}); err == nil {
		t.Fatal("cancelled verification accepted")
	}
}

func TestCommittedUnsignedUniversalDylibRejected(t *testing.T) {
	archive, err := zip.OpenReader(filepath.Join("..", "..", "..", "fixtures", "ipas", "ipa-loader-framework-v3-universal.ipa"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	var body []byte
	for _, member := range archive.File {
		if strings.HasSuffix(member.Name, "/libFixtureMath.dylib") {
			input, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(input)
			input.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if body == nil {
		t.Fatal("committed universal dylib missing")
	}
	filename := filepath.Join(t.TempDir(), "universal.dylib")
	if err = os.WriteFile(filename, body, 0600); err != nil {
		t.Fatal(err)
	}
	parts, err := slices(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatal("universal fixture must retain both architectures")
	}
	if _, err = VerifyBinary(context.Background(), filename, Options{AllowAdHoc: true}); err == nil {
		t.Fatal("unsigned universal input accepted as signed")
	}
}

func TestExplicitSourceSignedBundle(t *testing.T) {
	bundle := os.Getenv("IPA_LOADER_TEST_VERIFY_BUNDLE")
	if bundle == "" {
		t.Skip("explicit source-signed offline bundle required")
	}
	options := Options{AllowAdHoc: os.Getenv("IPA_LOADER_TEST_VERIFY_ADHOC") == "1"}
	if cert := os.Getenv("IPA_LOADER_TEST_VERIFY_CERT"); cert != "" {
		var err error
		options.CertificateDER, err = os.ReadFile(cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	report, err := VerifyBundle(context.Background(), bundle, options)
	if err != nil {
		t.Fatal(err)
	}
	sliceCount := 0
	for _, image := range report.Images {
		sliceCount += image.Slices
	}
	t.Logf("verified %d code objects, %d Mach-O slices, %d resource hashes", len(report.Images), sliceCount, report.ResourceHashes)
	for _, image := range report.Images {
		if image.Slices > 1 {
			t.Run("reject second slice tampering", func(t *testing.T) {
				copyRoot := filepath.Join(t.TempDir(), "Copy.app")
				if err := os.CopyFS(copyRoot, os.DirFS(bundle)); err != nil {
					t.Fatal(err)
				}
				relative, err := filepath.Rel(bundle, image.Path)
				if err != nil {
					t.Fatal(err)
				}
				filename := filepath.Join(copyRoot, relative)
				body, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				parts, err := slices(body)
				if err != nil {
					t.Fatal(err)
				}
				_, limit, err := signature(parts[1])
				if err != nil {
					t.Fatal(err)
				}
				parts[1][limit-1] ^= 1
				if err = os.WriteFile(filename, body, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err = VerifyBundle(context.Background(), copyRoot, options); err == nil {
					t.Fatal("modified second architecture accepted")
				}
			})
			break
		}
	}
}
