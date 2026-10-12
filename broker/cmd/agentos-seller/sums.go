package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// sumFor returns the SHA-256 that sums lists for image's base name. It
// refuses a list without exactly one line for it.
func sumFor(image, sums string) ([]byte, error) {
	f, err := os.Open(sums)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	name := filepath.Base(image)
	var found []byte
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		n++
		h, err := hex.DecodeString(fields[0])
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("%s: the line for %s is not a SHA-256", sums, name)
		}
		found = h
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("%s has %d lines for %s, want 1", sums, n, name)
	}
	return found, nil
}

// fileSum is the SHA-256 of a file's content.
func fileSum(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// checkSum checks image against its line in sums (I8, C3: a CI-built
// image is what its SHA256SUMS lists).
func checkSum(image, sums string) error {
	want, err := sumFor(image, sums)
	if err != nil {
		return err
	}
	got, err := fileSum(image)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s does not match its line in %s", image, sums)
	}
	return nil
}
