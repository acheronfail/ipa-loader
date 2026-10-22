//go:build windows

// Validate a Windows release without loading Apple support or using accounts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"ipa-loader/app/internal/platform"
	"ipa-loader/app/internal/releaseaudit"
	"os"
	"path/filepath"
	"time"
)

func run() error {
	rootFlag := flag.String("root", "", "explicit Windows package root")
	write := flag.Bool("write-manifest", false, "write the final file/hash/import inventory")
	flag.Parse()
	if *rootFlag == "" {
		return errors.New("Select a Windows package directory")
	}
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		return err
	}
	for _, relative := range []string{"ipa-loader.exe", "licenses/Go-LICENSE"} {
		info, err := os.Lstat(filepath.Join(root, relative))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("Required package file missing: %s", relative)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err = platform.ValidateWindowsRuntime(ctx, root); err != nil {
		return err
	}
	records, err := releaseaudit.Inventory(root)
	if err != nil {
		return err
	}
	if *write {
		manifest := struct {
			Format   int                       `json:"format"`
			Platform string                    `json:"platform"`
			Files    []releaseaudit.FileRecord `json:"files"`
		}{1, "windows/amd64", records}
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if err = os.WriteFile(filepath.Join(root, "release-manifest.json"), data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("Windows runtime package verified: %d files; sharing hashes/sources valid; pure Go signing; PE imports use Windows system libraries.\n", len(records))
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
