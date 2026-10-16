package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/provagent"
)

// cliPinPath is where a provider image records the CLI version it pins,
// relative to the image's root. guest/codex/build-rootfs.sh writes its
// CODEX_VERSION here; an image without the file pins nothing.
const cliPinPath = "usr/lib/agentos/cli-version"

// cliPinMax bounds the file: a version and its newline, nothing more.
const cliPinMax = 64

// cliPin is the shape of a pinned version: dotted numbers and an optional
// pre-release or build suffix. Anything else pins nothing.
var cliPin = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.-]+)?$`)

// imagePins are the root directories of the registered images a provider
// declaration runs on, by image name (#1877). The pin is read from the
// directory at every gate check, the same directory vm creates the
// machine from, so a rebuilt or swapped image is checked as it is now,
// never by a version read earlier. agentosd's provider runner and setup's
// sign-in share one imagePins.
type imagePins map[string]string

// version is the CLI version image pins now, or "" when it pins none: an
// unregistered image, a missing or malformed file. "" never matches a
// qualification record (provagent Qualification.Complete), so the
// provider gate stays closed.
func (p imagePins) version(image string) string {
	dir, ok := p[image]
	if !ok {
		return ""
	}
	v, err := readCLIPin(dir)
	if err != nil {
		return ""
	}
	return v
}

// readImagePins keeps the directory of every registered image a
// declaration in decls runs on, and logs at start each such image that
// pins nothing (by name and why) or pins another version than its
// declaration's record, naming both versions, never the file's content.
// An unregistered image is already the worker tools' to report.
func readImagePins(imgs images, decls map[string]provagent.Declaration) imagePins {
	p := imagePins{}
	for _, d := range decls {
		dir, ok := imgs[d.Image]
		if !ok {
			continue
		}
		p[d.Image] = dir
		v, err := readCLIPin(dir)
		switch {
		case err != nil:
			log.Printf("image %q pins no CLI version (provider gate closed): %v", d.Image, err)
		case v != d.Q.CLIVersion:
			log.Printf("image %q pins CLI %s but the %s qualification record is for %q (provider gate closed)", d.Image, v, d.ID, d.Q.CLIVersion)
		}
	}
	return p
}

// readCLIPin reads dir's pinned CLI version. The path resolves inside dir
// only (os.Root): a symlink in the image cannot point the read at a host
// file. It opens without blocking, so a FIFO or device at the path cannot
// hold agentosd, and must be a regular file of at most cliPinMax bytes
// holding one version line.
func readCLIPin(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	f, err := root.OpenFile(cliPinPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", cliPinPath)
	}
	b, err := io.ReadAll(io.LimitReader(f, cliPinMax+1))
	if err != nil {
		return "", err
	}
	if len(b) > cliPinMax {
		return "", fmt.Errorf("%s is over %d bytes", cliPinPath, cliPinMax)
	}
	v := strings.TrimSuffix(string(b), "\n")
	if !cliPin.MatchString(v) {
		return "", errors.New(cliPinPath + " holds no version")
	}
	return v, nil
}
