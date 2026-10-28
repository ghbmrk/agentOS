package proc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
)

// The driver's key (DEVSLOT-drivers part b, point 3; b2b-2, #3590). The
// driver's template unit names two files in OpenFile=, which the service
// manager opens before exec and passes after the connection, named in
// LISTEN_FDNAMES: the kernel's per-clerk key socket, as clerk
// driver-<name> (KeyFDName), and the driver's own sealed device-key file,
// read-only (DeviceFDName). Both are graceful, so a device with no key
// runs with none. The key opens only the device file's one static slot,
// device/<name>, inside this process: the host never holds it, so no
// process holds two drivers' keys (CLK-1). This file links no socket,
// HTTP or TLS package (DEVSLOT-a-5): it reads the clerk's at-rest form
// itself rather than through broker/clerk, which links the mail transport.

// DriverEnv names the environment variable that gives the driver's name to
// its process; the driver's unit sets it (mkosi.finalize's DRIVER_TEMPLATE).
const DriverEnv = "AGENTOS_DRIVER"

// The descriptors' names in the template's OpenFile= lines.
const (
	KeyFDName    = "clerk-key"
	DeviceFDName = "device"
)

// maxDeviceFile bounds the device-key file read.
const maxDeviceFile = 64 << 10

// driverName is mkosi.finalize's DRIVER_NAME.
var driverName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,18}$`)

// ErrKeyFiles: the descriptors, the name or the device-key file are not
// what the template passes. The process serves nothing.
var ErrKeyFiles = errors.New("devslot: the driver's key files are not the template's")

// Lend is devslot.Env.Lend: one call with the device key, wiped after.
type Lend = func(fn func(key []byte) error) error

// keyFDs finds the key's and the device file's descriptors in systemd's
// LISTEN_PID, LISTEN_FDS and LISTEN_FDNAMES, or -1 for one not passed.
// With none of them set, neither was. Descriptor 3 is the connection
// (Accept=yes); a set that names it otherwise, names a file twice or
// belongs to another process is ErrKeyFiles.
func keyFDs(getenv func(string) string, pid int) (key, device int, err error) {
	key, device = -1, -1
	if getenv("LISTEN_PID") == "" && getenv("LISTEN_FDS") == "" && getenv("LISTEN_FDNAMES") == "" {
		return key, device, nil
	}
	n, err := strconv.Atoi(getenv("LISTEN_FDS"))
	names := strings.Split(getenv("LISTEN_FDNAMES"), ":")
	if getenv("LISTEN_PID") != strconv.Itoa(pid) || err != nil || n < 1 || n > 3 || len(names) != n || names[0] != "connection" {
		return -1, -1, ErrKeyFiles
	}
	for i, name := range names[1:] {
		fd := connFD + 1 + i
		switch {
		case name == KeyFDName && key < 0:
			key = fd
		case name == DeviceFDName && device < 0:
			device = fd
		default:
			return -1, -1, ErrKeyFiles
		}
	}
	return key, device, nil
}

// keyLend reads the descriptors the template passed and returns the Lend
// for the device key, or nil for a device with no key (neither file, or
// only one). It closes both descriptors.
func keyLend(getenv func(string) string, pid int) (Lend, error) {
	kfd, dfd, err := keyFDs(getenv, pid)
	if err != nil {
		return nil, err
	}
	var key, device *os.File
	if kfd >= 0 {
		key = os.NewFile(uintptr(kfd), KeyFDName)
		defer key.Close()
	}
	if dfd >= 0 {
		device = os.NewFile(uintptr(dfd), DeviceFDName)
		defer device.Close()
	}
	if key == nil || device == nil {
		return nil, nil
	}
	return lendFrom(getenv(DriverEnv), key, device)
}

// lendFrom reads driver name's clerk key from key and its sealed slot
// from device, checks that the key opens it, and returns the Lend.
func lendFrom(name string, key, device *os.File) (Lend, error) {
	if !driverName.MatchString(name) {
		return nil, ErrKeyFiles
	}
	k, err := clerkkey.Read(key, "driver-"+name)
	if err != nil {
		return nil, err
	}
	sk, err := k.Sealer()
	k.Wipe()
	if err != nil {
		return nil, err
	}
	defer clear(sk)
	blob, err := deviceSlot(device, name)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, ErrKeyFiles
	}
	// clerk's slotAAD: the seal binds the slot's kind and name.
	aad := []byte("agentos/clerk/slot/static/" + slotPrefix + name)
	open := func() ([]byte, error) { return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad) }
	// Opened once here, so a wrong key or a swapped slot fails at start.
	p, err := open()
	if err != nil {
		return nil, ErrKeyFiles
	}
	clear(p)
	return func(fn func(key []byte) error) error {
		p, err := open()
		if err != nil {
			return ErrKeyFiles
		}
		defer clear(p)
		return fn(p)
	}, nil
}

// slotPrefix is clerk.DeviceSlots: the only slots a device key comes from.
const slotPrefix = "device/"

// deviceSlot reads the device-key file, the clerk's at-rest form
// (clerk.Secrets.MarshalBinary: slot name to kind and sealed blob), and
// returns the one static slot device/<name>. Every other slot is dropped
// unopened. The file must be a regular file within maxDeviceFile.
func deviceSlot(f *os.File, name string) ([]byte, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size > maxDeviceFile {
		return nil, ErrKeyFiles
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDeviceFile+1))
	if err != nil || len(b) > maxDeviceFile {
		return nil, ErrKeyFiles
	}
	var m map[string]struct {
		Kind string `json:"kind"`
		Blob []byte `json:"blob"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, ErrKeyFiles
	}
	s, ok := m[slotPrefix+name]
	if !ok || s.Kind != "static" {
		return nil, ErrKeyFiles
	}
	return s.Blob, nil
}
