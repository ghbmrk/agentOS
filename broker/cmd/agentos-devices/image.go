package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
)

// driverName is mkosi.finalize's DRIVER_NAME: devslot's name alphabet, short
// enough that agentos-drv-NAME is a valid user name.
var driverName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,18}$`)

// maxImageFile bounds drivers.json and the pins file.
const maxImageFile = 4 << 20

// imageDriver is one entry of the image's drivers.json (DEVSLOT-image, part
// b1): the driver's name, its binary's SHA-256 and the declaration the
// image holds for it, which is the host's, never the driver's.
type imageDriver struct {
	Name   string
	SHA256 [32]byte
	Decl   devslot.Declaration
}

// entry is drivers.json's entry as mkosi.finalize's DRIVER_KEYS has it. The
// fields the host does not use (the repository, commit, class row and
// measure) are the manifest's and the kernel's (b3).
type entry struct {
	Name        string          `json:"name"`
	Repository  string          `json:"repository"`
	Commit      string          `json:"commit"`
	SHA256      string          `json:"sha256"`
	Declaration json.RawMessage `json:"declaration"`
	Classes     json.RawMessage `json:"classes"`
	Measure     json.RawMessage `json:"measure"`
}

// readJSON decodes the regular file at path into v: at most maxImageFile
// bytes, no field v lacks, and nothing after the one value.
func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxImageFile+1))
	if err != nil {
		return err
	}
	if len(b) > maxImageFile {
		return errors.New("too long")
	}
	return strictJSON(b, v)
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// loadImage reads drivers.json at path. Any malformed entry refuses the
// whole file: the build wrote it, and mkosi.finalize checked it, so a bad
// one is a damaged image, not a driver to skip.
func loadImage(path string) (map[string]imageDriver, error) {
	var doc struct {
		Drivers []entry `json:"drivers"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, fmt.Errorf("drivers.json at %s: %v", path, err)
	}
	out := map[string]imageDriver{}
	for _, e := range doc.Drivers {
		d, err := e.driver()
		if err != nil {
			return nil, fmt.Errorf("drivers.json at %s: %v", path, err)
		}
		if _, dup := out[d.Name]; dup {
			return nil, fmt.Errorf("drivers.json at %s: driver %s is listed twice", path, d.Name)
		}
		out[d.Name] = d
	}
	return out, nil
}

func (e entry) driver() (imageDriver, error) {
	if !driverName.MatchString(e.Name) {
		return imageDriver{}, fmt.Errorf("driver name %q is off the alphabet", e.Name)
	}
	d := imageDriver{Name: e.Name}
	sum, err := hex.DecodeString(e.SHA256)
	if err != nil || len(sum) != sha256.Size || hex.EncodeToString(sum) != e.SHA256 {
		return imageDriver{}, fmt.Errorf("driver %s: sha256 is not 64 lower-case hex digits", e.Name)
	}
	copy(d.SHA256[:], sum)
	if err := strictJSON(e.Declaration, &d.Decl); err != nil {
		return imageDriver{}, fmt.Errorf("driver %s: declaration: %v", e.Name, err)
	}
	return d, nil
}

// imageDialer is a driver's Dialer: before each operation it hashes the
// driver's binary and refuses one that is not drivers.json's, then connects
// to the driver's socket unit, which starts a fresh, sandboxed instance for
// the connection (Accept=yes, DEVSLOT-image).
type imageDialer struct {
	d    imageDriver
	bin  string // the driver's binary, under /usr (verity)
	sock string // the driver's socket unit's socket
	log  func(string)
}

// errBinary is a driver binary that differs from drivers.json's hash.
var errBinary = errors.New("devices: driver's binary is not the one drivers.json lists")

func (x imageDialer) Dial(ctx context.Context) (devhost.Conn, error) {
	if err := x.check(); err != nil {
		x.log("devices: driver " + x.d.Name + ": " + err.Error() + "; refused")
		return nil, err
	}
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "unix", x.sock)
	if err != nil {
		return nil, err
	}
	return c.(*net.UnixConn), nil
}

func (x imageDialer) check() error {
	f, err := os.Open(x.bin)
	if err != nil {
		return errBinary
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return errBinary
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return errBinary
	}
	if !bytes.Equal(h.Sum(nil), x.d.SHA256[:]) {
		return errBinary
	}
	return nil
}

// dialerFor is driver d's dialer under the image's drivers directory and
// the drivers' socket directory.
func dialerFor(d imageDriver, driversDir, socketDir string, log func(string)) imageDialer {
	return imageDialer{
		d:    d,
		bin:  filepath.Join(driversDir, d.Name, "driver"),
		sock: filepath.Join(socketDir, d.Name+".sock"),
		log:  log,
	}
}
