// Command agentos-camera is the core's camera clerk process (CAM-clerk part
// d, CAM-clerk-host, #3514; SPEC DEV-3, DEV-7, DEV-8, DEV-10, CLK-1, KRN-7,
// NET-2 Cameras). It runs broker/clerk/camera under its own uid (CLK-1),
// holding the core's camera client key and each camera's segment key in its
// own sealed store, and nothing else:
//
//	agentos-camera -dir /var/lib/agentos-camera \
//	    -owner-sock /run/agentos-camera/owner.sock -owner-uid 0 \
//	    -runsc /usr/lib/agentos/runsc -runsc-root /run/agentos-camera/runsc \
//	    -decode-root /usr/lib/agentos/images/camdecode \
//	    -cgroup /sys/fs/cgroup/agentos.slice/agentos-keeper.slice/agentos-keeper-camera.service
//
// -cgroup is the clerk's own unit's group, delegated to its user: the clerk
// moves itself into its leaf there before anything else, and each decoder
// sandbox's group is made beside it. runsc runs as the clerk's uid, in a
// user namespace it makes (gvisor.Runtime.Rootless).
//
// Its key comes from the kernel on descriptor 3 at each start
// (clerkkey.Key, as agentos-clerk-mail's). It serves one socket, admitting
// only the owner side's uid: the owner's tier-4 connect, capture turn-on,
// retention, re-pin and disconnect, which the owner side checks before it
// relays them (DEV-10, CH-3), the enforcer's listed nodes, STOP and RESUME
// (KRN-7), and STATUS. Every camera's frames go to the capture store (part
// c) and to its decoder sandbox (part b); none is logged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/procguard"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// clerkName is this clerk's name in its key's hand-off.
const clerkName = "camera"

// clientSlot is the core's camera client key's sealed slot (design point 1):
// a device slot, so DeviceKey lends it per signature and wipes it.
const clientSlot = clerk.DeviceSlots + "camera-client"

// limit is each camera's DEV-8 rate limit per kind; backoff bounds the
// redial of a node that is not streaming (tests shorten it).
var (
	limit   = camera.Limit{Burst: 6, Window: sweepEvery}
	backoff = camera.DefaultBackoff
)

func main() {
	log.SetFlags(0)
	if err := start(os.Args[1:], os.Stderr, os.NewFile(clerkkey.FD, "clerk-key")); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	dir, ownerSock                    string
	ownerUID                          int
	runsc, runscRoot, decodeRoot, cgr string
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-camera", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "the clerk's own state directory, closed to every other uid")
	fs.StringVar(&c.ownerSock, "owner-sock", "", "the owner side's socket")
	fs.IntVar(&c.ownerUID, "owner-uid", -1, "the owner side's uid, the only peer on owner-sock (agentosd's, root)")
	fs.StringVar(&c.runsc, "runsc", "", "the gVisor runtime the decoder sandboxes run under")
	fs.StringVar(&c.runscRoot, "runsc-root", "", "runsc's state directory, this clerk's own")
	fs.StringVar(&c.decodeRoot, "decode-root", "", "the decoder sandbox's read-only root, holding /agentos-camdecode")
	fs.StringVar(&c.cgr, "cgroup", "", "the clerk's own unit's cgroup v2 group, delegated to it: it moves into its leaf there, and each decoder sandbox's group is made beside it")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !abs(c.dir, c.ownerSock, c.runsc, c.runscRoot, c.decodeRoot, c.cgr):
		return c, errors.New("-dir, -owner-sock, -runsc, -runsc-root, -decode-root and -cgroup are required, as absolute paths")
	case c.ownerUID < 0:
		return c, errors.New("-owner-uid is required")
	}
	return c, nil
}

func abs(paths ...string) bool {
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return false
		}
	}
	return true
}

// start refuses a bad command line before the key is read, so a clerk that
// cannot start never takes it.
func start(args []string, stderr io.Writer, keyFile *os.File) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// Not as its owner side's uid, and not dumpable, since a decoder under
	// the clerk's own uid could then read the keys from its memory (CLK-1).
	if err := procguard.Isolate(c.ownerUID); err != nil {
		return err
	}
	// The kernel hands the key only to a peer in the unit's own group, so
	// the clerk leaves it for its leaf only once it holds the key.
	sec, err := openSecrets(c.dir, keyFile)
	if err != nil {
		return err
	}
	rt, err := decoders(c)
	if err != nil {
		return err
	}
	logf := func(m string) { log.Print(m) }
	h, err := newHost(c.dir, sec, nil, camera.GVisor(rt), c.decodeRoot, c.cgr, logf)
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
	go func() { h.tick(ctx, sweepEvery); close(done) }()
	go serve(ln, h)
	<-ctx.Done()
	ln.Close()
	<-done
	return nil
}

// leaf is the clerk's own group under -cgroup.
const leaf = "clerk"

// decoders moves the clerk, once it holds its key, into its leaf of its
// unit's delegated group and returns the runtime its decoder sandboxes start
// under, beside the leaf (CAM-host-11). cgroup v2 lets a group that holds a process give its
// children no controller, so the clerk leaves its unit's group before a
// sandbox's group, with its memory cap, is made there. runsc runs as the
// clerk's own uid, which is not root (CLK-1), so it runs rootless.
func decoders(c config) (*gvisor.Runtime, error) {
	g := &cgroup.Group{Path: filepath.Join(c.cgr, leaf)}
	if err := os.Mkdir(g.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := g.Join(0); err != nil {
		return nil, fmt.Errorf("joining %s: %w", g.Path, err)
	}
	return &gvisor.Runtime{Bin: c.runsc, StateDir: c.runscRoot, Platform: "systrap", Rootless: true}, nil
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

// segmentKeys binds the store's SegmentKeys to the sealed store: one static
// device slot per camera under camera.SegmentSlots (CAM-clerk-11).
type segmentKeys struct{ s *clerk.Secrets }

func (k segmentKeys) Make(id string) error {
	if k.s.Has(camera.SegmentSlots + id) {
		return nil
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	return k.s.Put(camera.SegmentSlots+id, clerk.KindStatic, key)
}

func (k segmentKeys) Lend(id string, fn func(key []byte) error) error {
	return k.s.DeviceKey(camera.SegmentSlots + id)(fn)
}

func (k segmentKeys) Erase(id string) error { return k.s.Remove(camera.SegmentSlots + id) }

// eventSink logs each tamper event as a fixed line of the camera's ID, the
// kind and the count (design point 6) until the kernel's device-report
// entry exists (DEVSLOT b3, DEVSLOT-kernel; CAM-host-3).
type eventSink struct{ log func(string) }

func (s eventSink) Emit(e camera.Event) error {
	n := max(e.Coalesced, 1)
	s.log(fmt.Sprintf("camera %s: event %s x%d (verified; the kernel's device-report side is DEVSLOT b3's)", e.Camera, e.Kind, n))
	return nil
}

// newHost builds the clerk, the store and the decoder sandboxes over sec.
// connect, if set, replaces the guard's final connect (tests).
func newHost(dir string, sec *clerk.Secrets, connect func(context.Context, string, string) (net.Conn, error),
	startDec camera.StartFunc, decodeRoot, cgr string, logf func(string)) (*host, error) {
	return newHostWith(dir, sec, connect, logf, func(report func(string, camera.Kind)) (decoder, error) {
		return camera.NewDecoder(camera.DecodeConfig{
			Start: startDec, Root: decodeRoot, Cgroup: cgr,
			// The decoded frames' consumers (VIS-core, live view) are later
			// rows: until then each checked frame is dropped (CAM-host-5).
			Out:    func(camera.Decoded) {},
			Report: report,
			Log:    logf,
		})
	})
}

// newHostWith is newHost with the decoder made by newDec (tests give a
// fake feed).
func newHostWith(dir string, sec *clerk.Secrets, connect func(context.Context, string, string) (net.Conn, error),
	logf func(string), newDec func(report func(string, camera.Kind)) (decoder, error)) (*host, error) {
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	if !sec.Has(clientSlot) {
		if err := camera.NewClientKey(func(raw []byte) error { return sec.Put(clientSlot, clerk.KindStatic, raw) }); err != nil {
			return nil, err
		}
		logf("camera: a client key was made; give its public key to the enforcer for the nodes' bundles")
	}
	key, err := camera.OpenClientKey(sec.DeviceKey(clientSlot))
	if err != nil {
		return nil, err
	}
	store, err := camera.NewStore(camera.StoreConfig{Dir: filepath.Join(dir, "capture"), Keys: segmentKeys{sec}, Log: logf})
	if err != nil {
		return nil, err
	}
	deny := func(e netguard.DenyEvent) {
		logf(fmt.Sprintf("netguard: refused %v port %d: %s", e.Addr, e.Port, e.Reason))
	}
	guard := netguard.New(netguard.Config{OnDeny: deny, Connect: connect})
	h := &host{dir: dir, store: store, guard: guard, log: logf}
	var cl *camera.Clerk
	dec, err := newDec(func(id string, k camera.Kind) { cl.Report(id, k) })
	if err != nil {
		return nil, err
	}
	cl, err = camera.New(camera.Config{
		Guard: guard, Key: key, Frames: tee{store, dec}, Events: eventSink{logf}, Limit: limit,
		// RES-2: the host admits at most maxCameras (CAM-host-4).
		Admit:   func(string) bool { return true },
		Backoff: backoff,
		Log:     logf,
	})
	if err != nil {
		return nil, err
	}
	h.clerk, h.dec, h.point = cl, dec, key.Point()
	return h, nil
}

// The owner socket's calls. Each answer is fixed text or the host's
// STATUS lines; none carries a frame or a key but the client's public key.
type (
	connectArgs   = record
	captureArgs   struct{ ID, Capture string }
	retentionArgs struct {
		ID           string
		RetentionSec int64 `json:"retention_sec"`
	}
	repinArgs      struct{ ID, Addr, Key string }
	disconnectArgs struct{ ID string }
	listedArgs     struct{ Nodes []listed }
	statusAnswer   struct {
		Lines []string `json:"lines"`
		// Client is the core's camera client public key (uncompressed
		// P-256, hex), for the enforcer to put in the nodes' bundles.
		Client string `json:"client"`
	}
)

// ops are the owner socket's calls.
var ops = map[string]func(h *host, args json.RawMessage) (any, error){
	"camera/connect": func(h *host, a json.RawMessage) (any, error) {
		var r connectArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.connect(r)
	},
	"camera/capture": func(h *host, a json.RawMessage) (any, error) {
		var r captureArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.setCapture(r.ID, r.Capture)
	},
	"camera/retention": func(h *host, a json.RawMessage) (any, error) {
		var r retentionArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.setRetention(r.ID, r.RetentionSec)
	},
	"camera/repin": func(h *host, a json.RawMessage) (any, error) {
		var r repinArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.repin(r.ID, r.Addr, r.Key)
	},
	"camera/disconnect": func(h *host, a json.RawMessage) (any, error) {
		var r disconnectArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.disconnect(r.ID)
	},
	"camera/listed": func(h *host, a json.RawMessage) (any, error) {
		var r listedArgs
		if err := decode(a, &r); err != nil {
			return nil, err
		}
		return nil, h.setListed(r.Nodes)
	},
	"camera/stop":   func(h *host, _ json.RawMessage) (any, error) { return nil, h.stop() },
	"camera/resume": func(h *host, _ json.RawMessage) (any, error) { return nil, h.resume() },
	"camera/status": func(h *host, _ json.RawMessage) (any, error) {
		return statusAnswer{Lines: h.status(), Client: hex.EncodeToString(h.point[:])}, nil
	},
}

// decode reads one call's arguments strictly: an unknown field is refused.
func decode(a json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(a))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errRecord
	}
	return nil
}

// serve answers the owner side's calls on ln until it closes.
func serve(ln net.Listener, h *host) error {
	return proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(name string, args json.RawMessage) (json.RawMessage, error) {
			f, ok := ops[name]
			if !ok {
				return nil, errors.New("camera: the owner socket has no call " + name)
			}
			res, err := f(h, args)
			if err != nil || res == nil {
				return nil, err
			}
			return json.Marshal(res)
		})
	})
}
