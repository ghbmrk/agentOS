package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"

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

// imagePins are the CLI versions the registered images pin, by image name
// (#1877). They are read once at start, so agentosd's provider runner and
// setup's sign-in see the same pin, the one the image on disk carried.
type imagePins map[string]string

// version is the CLI version image pins, or "" when it pins none: an
// unregistered image, a missing or malformed file. "" never matches a
// qualification record (provagent Qualification.Complete), so the
// provider gate stays closed.
func (p imagePins) version(image string) string { return p[image] }

// readImagePins reads the pin of every registered image a declaration in
// decls runs on. A registered provider image that pins nothing is logged
// by name and why, never with the file's content; an unregistered one is
// already the worker tools' to report.
func readImagePins(imgs images, decls map[string]provagent.Declaration) imagePins {
	p := imagePins{}
	for _, d := range decls {
		dir, ok := imgs[d.Image]
		if !ok {
			continue
		}
		name := d.Image
		v, err := readCLIPin(dir)
		if err != nil {
			log.Printf("image %q pins no CLI version (provider gate closed): %v", name, err)
			continue
		}
		p[name] = v
	}
	return p
}

// readCLIPin reads dir's pinned CLI version. The path resolves inside dir
// only (os.Root): a symlink in the image cannot point the read at a host
// file. The file must be a regular file of at most cliPinMax bytes holding
// one version line.
func readCLIPin(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	f, err := root.Open(cliPinPath)
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
