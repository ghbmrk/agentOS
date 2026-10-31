// Command agentos-homekit is the core's HomeKit clerk process (DEV-homekit
// part b2a, #3891; SPEC DEV-3, DEV-8, DEV-10, CLK-1, KRN-7, A16, CH-3,
// CH-6). It runs broker/clerk/homekit under its own uid (CLK-1), holding the
// box's HomeKit controller key in its own sealed store, and nothing else:
//
//	agentos-homekit -dir /var/lib/agentos-homekit \
//	    -owner-sock /run/agentos-homekit/owner.sock -owner-uid 0
//
// Its key comes from the kernel on descriptor 3 at each start
// (clerkkey.Key, as agentos-camera's). It serves one socket, admitting only
// the owner side's uid: the accessories the enforcer lists, the owner's
// tier-4 connect by HomeKit code, bounds and re-pin, which the owner side
// checks before it relays them (DEV-10, CH-3), the disconnect, STOP and
// RESUME (KRN-7), and STATUS. It serves no write to a thermostat: a
// planner's write waits for the kernel's class table (b2d, design point 7).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/homekit"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/procguard"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// clerkName is this clerk's name in its key's hand-off.
const clerkName = "homekit"

// ctrlSlot is the controller key's sealed slot (design point 1): a device
// slot, so DeviceKey lends it per signature and wipes it (HK-14).
const ctrlSlot = clerk.DeviceSlots + "homekit/controller"

// limit is each device and characteristic's DEV-8 rate limit; backoff
// bounds the redial of a dropped link; pollEvery is how often an open link
// reads its thermostat (tests shorten them).
var (
	limit     = devhost.Limit{Burst: 6, Window: time.Minute}
	backoff   = struct{ Min, Max time.Duration }{time.Second, 5 * time.Minute}
	pollEvery = time.Minute
)

func main() {
	log.SetFlags(0)
	if err := start(os.Args[1:], os.Stderr, os.NewFile(clerkkey.FD, "clerk-key")); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	dir, ownerSock string
	ownerUID       int
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-homekit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "the clerk's own state directory, closed to every other uid")
	fs.StringVar(&c.ownerSock, "owner-sock", "", "the owner side's socket")
	fs.IntVar(&c.ownerUID, "owner-uid", -1, "the owner side's uid, the only peer on owner-sock (agentosd's, root)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !filepath.IsAbs(c.dir) || !filepath.IsAbs(c.ownerSock):
		return c, errors.New("-dir and -owner-sock are required, as absolute paths")
	case c.ownerUID < 0:
		return c, errors.New("-owner-uid is required")
	}
	return c, nil
}

// start refuses a bad command line before the key is read, so a clerk that
// cannot start never takes it.
func start(args []string, stderr io.Writer, keyFile *os.File) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	// A malformed devices file refuses the start before the key is read
	// too; start reads it again.
	if err := privfile.Check(c.dir, true); err != nil {
		return err
	}
	if _, _, err := load(c.dir); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// Not as its owner side's uid, and not dumpable, before the key is
	// read (CLK-1): no process under its uid can read the controller key
	// from its memory.
	if err := procguard.Isolate(c.ownerUID); err != nil {
		return err
	}
	sec, err := openSecrets(c.dir, keyFile)
	if err != nil {
		return err
	}
	logf := func(m string) { log.Print(m) }
	h, err := newHost(c.dir, sec, nil, logf)
	if err != nil {
		return err
	}
	ln, err := sockets.ListenPeers(c.ownerSock, c.ownerUID)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := h.start(ctx); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { h.tick(ctx, limit.Window); close(done) }()
	go serve(ln, h)
	<-ctx.Done()
	ln.Close()
	<-done
	return nil
}

// openSecrets reads the clerk's key from the kernel's hand-off and opens
// its sealed store in dir.
func openSecrets(dir string, keyFile *os.File) (*clerk.Secrets, error) {
	k, err := clerkkey.Read(keyFile, clerkName)
	if err != nil {
		return nil, err
	}
	sk, err := k.Sealer()
	k.Wipe()
	if err != nil {
		return nil, err
	}
	sealer, err := clerk.NewAESSealer(sk)
	clear(sk)
	if err != nil {
		return nil, err
	}
	return run.OpenSecrets(dir, sealer)
}

// pairer is the clerk as the host uses it (*homekit.Clerk through
// clerkPairer; the tests give a fake that keeps its contract, HK-host-9).
type pairer interface {
	Connect(ctx context.Context, name, addr, code string) ([]homekit.Device, error)
	Resolve(ctx context.Context, d *homekit.Device) ([]homekit.Device, error)
	Open(ctx context.Context, d *homekit.Device) (link, error)
}

// link is one open session with a thermostat (*homekit.Link).
type link interface {
	Poll() (int, error)
	Config(c int) error
	ConfirmBounds(typ string, lo, hi float64) error
	RemovePairing() error
	Close() error
	Dropped() int
	Refused() int
}

type clerkPairer struct{ *homekit.Clerk }

func (c clerkPairer) Open(ctx context.Context, d *homekit.Device) (link, error) {
	l, err := c.Clerk.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// newHost builds the clerk over sec, making the controller key at first
// start. connect, if set, replaces the guard's final connect (tests).
func newHost(dir string, sec *clerk.Secrets, connect func(context.Context, string, string) (net.Conn, error), logf func(string)) (*host, error) {
	return newHostWith(dir, sec, connect, logf, func(g *netguard.Policy, kh homekit.KeyHolder, emit func(homekit.Event) error) pairer {
		return clerkPairer{&homekit.Clerk{Keys: kh, Guard: g, Emit: emit, Log: logf}}
	})
}

// newHostWith is newHost with the clerk made by mk.
func newHostWith(dir string, sec *clerk.Secrets, connect func(context.Context, string, string) (net.Conn, error),
	logf func(string), mk func(*netguard.Policy, homekit.KeyHolder, func(homekit.Event) error) pairer) (*host, error) {
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	if !sec.Has(ctrlSlot) {
		if err := homekit.NewControllerKey(func(seed []byte) error { return sec.Put(ctrlSlot, clerk.KindStatic, seed) }); err != nil {
			return nil, err
		}
		logf("homekit: a controller key was made")
	}
	kh, err := homekit.NewSealedKeyHolder(sec.DeviceKey(ctrlSlot))
	if err != nil {
		return nil, err
	}
	deny := func(e netguard.DenyEvent) {
		logf(fmt.Sprintf("netguard: refused %v port %d: %s", e.Addr, e.Port, e.Reason))
	}
	h := &host{dir: dir, log: logf, guard: netguard.New(netguard.Config{OnDeny: deny, Connect: connect})}
	h.events = newLimiter(limit, time.Now)
	var setup [32]byte
	if _, err := rand.Read(setup[:]); err != nil {
		return nil, err
	}
	h.setupKey = sha256.Sum256(setup[:])
	h.pairing = kh.PairingID()
	h.p = mk(h.guard, kh, h.events.emit)
	return h, nil
}

// The owner socket's calls. Each answer is fixed text or the host's
// STATUS; none carries a HomeKit code, a key or an accessory's text.
type (
	connectArgs struct {
		Name, Device string
		Code         string `json:"code"`
	}
	boundsArgs struct {
		Name, Char string
		Min, Max   float64
	}
	repinArgs struct {
		Name, Device string
		Code         string `json:"code"`
	}
	nameArgs         struct{ Name string }
	listedArgs       struct{ Accessories []listed }
	disconnectAnswer struct {
		// Removed says the accessory took the remove-pairing; false means
		// the device was dropped here only, and the owner resets HomeKit on
		// the thermostat.
		Removed bool `json:"removed"`
	}
)

// ops are the owner socket's calls: a closed table (design point 2).
var ops = map[string]func(h *host, args json.RawMessage) (any, error){
	"homekit/listed": func(h *host, a json.RawMessage) (any, error) {
		var r listedArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.setListed(r.Accessories)
	},
	"homekit/connect": func(h *host, a json.RawMessage) (any, error) {
		var r connectArgs
		err := decode(a, &r)
		defer clearString(&r.Code)
		if err != nil {
			return nil, err
		}
		return nil, h.connect(r.Name, r.Device, r.Code)
	},
	"homekit/bounds": func(h *host, a json.RawMessage) (any, error) {
		var r boundsArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.bounds(r.Name, r.Char, r.Min, r.Max)
	},
	"homekit/repin": func(h *host, a json.RawMessage) (any, error) {
		var r repinArgs
		err := decode(a, &r)
		defer clearString(&r.Code)
		if err != nil {
			return nil, err
		}
		return nil, h.repin(r.Name, r.Device, r.Code)
	},
	"homekit/disconnect": func(h *host, a json.RawMessage) (any, error) {
		var r nameArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		removed, err := h.disconnect(r.Name)
		if err != nil {
			return nil, err
		}
		return disconnectAnswer{Removed: removed}, nil
	},
	"homekit/stop":   func(h *host, _ json.RawMessage) (any, error) { return nil, h.stop() },
	"homekit/resume": func(h *host, _ json.RawMessage) (any, error) { return nil, h.resume() },
	"homekit/status": func(h *host, _ json.RawMessage) (any, error) { return h.status(), nil },
}

// clearString drops the reference to a HomeKit code once the call is done;
// Go strings cannot be wiped, so this only shortens what holds it.
func clearString(s *string) { *s = "" }

// decode reads one call's arguments strictly: an unknown field is refused,
// and the refusal names nothing the call carried.
func decode(a json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(a))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errArgs
	}
	return nil
}

// serve answers the owner side's calls on ln until it closes.
func serve(ln net.Listener, h *host) error {
	return proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(name string, args json.RawMessage) (json.RawMessage, error) {
			f, ok := ops[name]
			if !ok {
				return nil, errors.New("homekit: the owner socket has no such call")
			}
			res, err := f(h, args)
			if err != nil || res == nil {
				return nil, err
			}
			return json.Marshal(res)
		})
	})
}
