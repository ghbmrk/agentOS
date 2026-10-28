// Command agentos-devices is the device-driver host's process (DEVSLOT-drivers
// part b2b): the host that runs every image driver's operations, under its own
// uid with no key, outside every driver's address space (D-189):
//
//	agentos-devices -drivers /usr/lib/agentos/drivers.json [-pins FILE] [-home 2001:db8:0:100::/56]
//
// It reads the image's drivers.json (part b1) and, for each pinned device,
// builds one broker/clerk/devhost.Host from the image's declaration, never
// the driver's. Before each operation it hashes the driver's binary against
// drivers.json and refuses one that differs, then connects to the driver's
// socket unit, which starts a fresh, sandboxed instance for that one
// operation. It owns the transport: a TLS stream to a TCP device, kept only
// when the device's key is the pin's (DEV-3), and a fixed "no relay" error
// for GATT until the enforcer's relay (part c). The kernel's socket side and
// the device-report entry are b3's; the per-driver key hand-off and the CI
// boot probe are b2b-2's (#3473).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
)

// hostUID is the host's uid, fixed by its sysusers line so the driver
// template can name it for the driver's peer check (devslot/proc's
// HostUIDEnv; mkosi.finalize's DEVHOST_UID).
const hostUID = 900

// The host's fixed operating values (DEVSLOT-host-lib-6 and -8). The
// operation deadline and the subscription's are within the template's
// RuntimeMaxSec=120, so the host ends an operation before PID 1 kills it.
var (
	opDeadline  = 60 * time.Second
	subDeadline = 100 * time.Second
	limit       = devhost.Limit{Burst: 6, Window: time.Minute}
)

// The image's paths. The drivers' socket directory is the template's
// (ListenStream=), and only the template may name it (mkosi.finalize's
// DRIVER_MARKS), so it is not on the unit's command line.
const (
	defaultDrivers   = "/usr/lib/agentos/drivers.json"
	defaultSocketDir = "/run/agentos-drivers"
)

func main() {
	log.SetFlags(0)
	c, err := parse(os.Args[1:], os.Stderr)
	if err != nil {
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	drivers, driversDir, socketDir, pins string
	home                                 netip.Prefix
	// uid is the uid the process must run as: hostUID, or the test's own.
	uid int
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-devices", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := config{uid: hostUID}
	var home string
	fs.StringVar(&c.drivers, "drivers", defaultDrivers, "the image's drivers.json")
	fs.StringVar(&c.pins, "pins", "", "the paired devices' pins; empty or missing: no device is paired")
	fs.StringVar(&home, "home", "", "the uplink's enclosing /56, inside which a global IPv6 pin is home (DEV-2)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 || !filepath.IsAbs(c.drivers) || c.pins != "" && !filepath.IsAbs(c.pins) {
		err := errors.New("agentos-devices: -drivers and -pins are absolute paths, and there are no arguments")
		fmt.Fprintln(stderr, err)
		return c, err
	}
	if home != "" {
		p, err := netip.ParsePrefix(home)
		if err != nil || p.Bits() != 56 || !p.Addr().Is6() || p.Masked() != p {
			err := errors.New("agentos-devices: -home is an IPv6 /56")
			fmt.Fprintln(stderr, err)
			return c, err
		}
		c.home = p
	}
	c.driversDir = filepath.Join(filepath.Dir(c.drivers), "drivers")
	c.socketDir = defaultSocketDir
	return c, nil
}

// pinFile is the pins file: one device per driver, which pairing writes
// (a later row). Key is the hex SHA-256 of a TCP device's public key.
type pinFile struct {
	Pins []struct {
		Driver  string `json:"driver"`
		Address string `json:"address,omitempty"`
		Host    string `json:"host,omitempty"`
		Key     string `json:"key,omitempty"`
	} `json:"pins"`
}

// pinned is one paired device: its driver and its pin.
type pinned struct {
	driver string
	pin    devslot.Pin
}

func loadPins(path string) ([]pinned, error) {
	if path == "" {
		return nil, nil
	}
	var f pinFile
	if err := readJSON(path, &f); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("pins at %s: %v", path, err)
	}
	var out []pinned
	for _, p := range f.Pins {
		pin := devslot.Pin{Address: p.Address}
		if p.Host != "" {
			a, err := netip.ParseAddr(p.Host)
			if err != nil {
				return nil, fmt.Errorf("pins at %s: driver %s: host is not an address", path, p.Driver)
			}
			pin.Host = a
		}
		if p.Key != "" {
			k, err := hex.DecodeString(p.Key)
			if err != nil || len(k) != len(pin.Key) {
				return nil, fmt.Errorf("pins at %s: driver %s: key is not a hex SHA-256", path, p.Driver)
			}
			copy(pin.Key[:], k)
		}
		if slices.ContainsFunc(out, func(q pinned) bool { return q.driver == p.Driver }) {
			return nil, fmt.Errorf("pins at %s: driver %s is pinned twice", path, p.Driver)
		}
		out = append(out, pinned{p.Driver, pin})
	}
	return out, nil
}

// dropSink takes the host's events until the kernel's device-report side
// exists (b3): it counts them and logs that count, never a reading, which
// is private data (DEV-8).
type dropSink struct {
	driver string
	log    func(string)
}

func (s dropSink) Emit(devhost.Event) error {
	s.log("devices: driver " + s.driver + ": an event dropped; the kernel's device-report side is b3's")
	return nil
}

// hosts builds a host for each pinned device whose driver drivers.json
// lists. A pin for any other driver is refused and logged, and starts
// nothing: only image drivers run (TestHostStartsOnlyImageDrivers).
func hosts(c config, image map[string]imageDriver, pins []pinned, logf func(string)) map[string]*devhost.Host {
	out := map[string]*devhost.Host{}
	for _, p := range pins {
		d, ok := image[p.driver]
		if !ok {
			logf(fmt.Sprintf("devices: a pin names driver %q, which drivers.json does not list; refused", p.driver))
			continue
		}
		t, err := transportFor(d.Decl, p.pin)
		if err == nil {
			var h *devhost.Host
			h, err = devhost.New(devhost.Config{
				Decl:         d.Decl,
				Pin:          p.pin,
				Home:         c.home,
				Dialer:       dialerFor(d, c.driversDir, c.socketDir, logf),
				Transport:    t,
				Sink:         dropSink{d.Name, logf},
				Deadline:     opDeadline,
				Subscription: subDeadline,
				Limit:        limit,
				Log:          logf,
			})
			if err == nil {
				out[d.Name] = h
				continue
			}
		}
		logf("devices: driver " + d.Name + ": its pin or declaration is refused: " + err.Error())
	}
	return out
}

// run starts the hosts and flushes each one's DEV-8 windows until ctx ends.
func run(ctx context.Context, c config) error {
	if os.Getuid() != c.uid {
		return fmt.Errorf("agentos-devices: runs as uid %d, the drivers' peer check's, not %d", c.uid, os.Getuid())
	}
	image, err := loadImage(c.drivers)
	if err != nil {
		return err
	}
	pins, err := loadPins(c.pins)
	if err != nil {
		return err
	}
	logf := func(m string) { log.Print(m) }
	hs := hosts(c, image, pins, logf)
	logf(fmt.Sprintf("devices: %d drivers in the image, %d paired devices", len(image), len(hs)))
	tick := time.NewTicker(limit.Window)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			for _, h := range hs {
				h.Flush()
			}
		}
	}
}
