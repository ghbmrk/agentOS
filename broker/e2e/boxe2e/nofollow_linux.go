package main

import (
	"io"
	"os"
	"syscall"
)

// The harness runs as root (image/e2e/agentos-e2e.service), so it reads
// and writes its named files without following a link at the final name
// (REV-CHK-links, #3946): some sit in directories another uid owns, such
// as agentos-localui's card latch.

// readNoFollow reads path, refusing a link at its final name.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// writeNoFollow writes b to path as os.WriteFile does, refusing a link at
// its final name.
func writeNoFollow(path string, b []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
