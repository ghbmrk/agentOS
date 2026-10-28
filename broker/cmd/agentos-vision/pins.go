package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// models.pins names each file the runtime loads with its SHA-256 (VIS-A27).
//
//go:embed models.pins
var modelPins string

// maxPinned bounds a pinned file's size: the runtime library is about
// 28 MB and the detector 20 MB.
const maxPinned = 64 << 20

// pinFor is the pinned SHA-256 of file, or "".
func pinFor(file string) string {
	for _, line := range strings.Split(modelPins, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && !strings.HasPrefix(f[0], "#") && f[1] == file {
			return f[0]
		}
	}
	return ""
}

// readPinned reads file from dir and checks it against its pin: ErrMissing
// when it is absent, ErrRefused when it is not a regular file, is larger
// than maxPinned, or its hash is not the pinned one. The bytes returned
// are the ones hashed, so what loads is what was checked.
func readPinned(dir, file string) ([]byte, error) {
	want := pinFor(file)
	if want == "" {
		return nil, fmt.Errorf("%w: %s is not pinned", ErrRefused, file)
	}
	f, err := os.Open(filepath.Join(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrRefused, file)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPinned+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if len(b) > maxPinned || hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("%w: %s does not match its pin", ErrRefused, file)
	}
	return b, nil
}
