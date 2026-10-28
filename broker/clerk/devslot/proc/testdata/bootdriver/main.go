// Command bootdriver is the CI boot probe's fixture driver (image/ci_boot.sh,
// DEVSLOT-drivers b2b-2, #3590): a real devslot.Driver under the real
// proc.Main, run as an instance of the driver template rendered for the
// name "fixture". Its operation "probe" reports what the sandbox lets it
// do, as readings (1 refused, 0 allowed), and what Secrets.Open lends; its
// operation "hang" never returns, so only PID 1's RuntimeMaxSec= ends it.
// It sleeps rather than blocking forever: a Go program whose goroutines all
// block with no timer pending aborts as deadlocked, which would end the
// instance before the kill could be seen (#3642 Security point 1).
// It is test tooling, so it imports what a driver may not (os, syscall): a
// driver could never make these checks itself.
package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The canaries bootprobe seals in the fixture's device-key file: the
// fixture's own slot, and another beside it.
const keyCanary, otherCanary = "canary-devkey-boot-0001", "canary-devkey-boot-0002"

type fixture struct{}

func (fixture) Declare() devslot.Declaration {
	return devslot.Declaration{
		Device:      "fixture",
		Link:        devslot.GATT,
		Channels:    []devslot.Channel{{Name: "data", Service: "fff0", Char: "fff1"}},
		Operations:  []devslot.Operation{{Name: "probe", Verb: key.Read}, {Name: "hang", Verb: key.Read}},
		Readings:    []string{"inet", "unix", "passwd", "root", "stdin", "key"},
		MaxRead:     1,
		MaxReadings: 6,
	}
}

func refused(err error) int64 {
	if err != nil {
		return 1
	}
	return 0
}

func (fixture) Run(ctx context.Context, op string, _ devslot.Link, s devslot.Secrets) ([]devslot.Reading, error) {
	if op == "hang" {
		for { // ignores ctx, as a hostile driver would
			time.Sleep(time.Hour)
		}
	}
	r := func(kind string, v int64) devslot.Reading {
		return devslot.Reading{Kind: kind, Value: v, Time: time.Unix(1e9, 0).UTC()}
	}
	inet, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.Close(inet)
	}
	unix, uerr := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if uerr == nil {
		syscall.Close(unix)
	}
	// 1: /etc/passwd is not there at all (ENOENT), not merely unreadable.
	f, perr := os.Open("/etc/passwd")
	if perr == nil {
		f.Close()
	}
	passwd := int64(0)
	if errors.Is(perr, syscall.ENOENT) {
		passwd = 1
	}
	// 1: the root is a tmpfs (TemporaryFileSystem=/) with no /etc or /var.
	root := int64(0)
	var fs syscall.Statfs_t
	_, eerr := os.Lstat("/etc")
	_, verr := os.Lstat("/var")
	if syscall.Statfs("/", &fs) == nil && fs.Type == 0x01021994 && errors.Is(eerr, syscall.ENOENT) && errors.Is(verr, syscall.ENOENT) {
		root = 1
	}
	// 1: descriptor 0 is /dev/null (character device 1:3).
	var st syscall.Stat_t
	stdin := int64(0)
	if syscall.Fstat(0, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFCHR && st.Rdev == 1<<8|3 {
		stdin = 1
	}
	// 1: the fixture's slot; 2: the other slot; 3: no key; 0: else.
	k := int64(0)
	if err := s.Open(func(b []byte) error {
		switch string(b) {
		case keyCanary:
			k = 1
		case otherCanary:
			k = 2
		}
		return nil
	}); err == devslot.ErrNoKey {
		k = 3
	}
	return []devslot.Reading{r("inet", refused(err)), r("unix", refused(uerr)), r("passwd", passwd), r("root", root), r("stdin", stdin), r("key", k)}, nil
}

func main() { proc.Main(fixture{}) }
