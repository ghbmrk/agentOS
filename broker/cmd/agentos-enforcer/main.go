// Command agentos-enforcer is the enforcer's daemon (briefs/ENF.md slice
// l, ENF-l-a #3670): it wires the policy engine, the page, enrolment, the
// channel, the firewall, the alerts and the head copies into one process
// on the enforcer box, and owns the lifecycle matrix (lifecycle_test.go).
//
// It is enforcer code (brief decision 1, broker/daemon/arc2_test.go): it
// links the enforcer's packages, broker/kernel/key and x/sys/unix for
// CLOCK_BOOTTIME, and nothing else of agentOS.
//
//	agentos-enforcer -state DIR -provision CASEFILE -ap-setup SETUPFILE   first boot only
//	agentos-enforcer -state DIR -channel-pub          print the channel key
//	agentos-enforcer -state DIR -ap-pub               print the access points' login key
//	agentos-enforcer -state DIR -config FILE          run
//
// The case code and the setup network's password (the sticker's) are read
// from files, never an argument or the environment. The access points
// are wired (apnet.go, ENF-l-b2 part a), as are the resolver, the pair
// relay, Wake-on-LAN and the byte caps (ENF-l-b1); ENF-l-b2 parts b and c
// wire the radios and device secrets, and until then every radio command
// is refused (noRadio). Its assumptions are in ASSUMPTIONS.md.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	dnsrun "github.com/ghbmrk/agentos/broker/enforcer/dns/run"
	"github.com/ghbmrk/agentos/broker/enforcer/mdns"
	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/offload"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/enforcer/wol"
)

// init keeps the main goroutine on the main thread, and every other
// goroutine off it. confine runs each step inside a radio stack's network
// namespace on a goroutine that locks its thread, moves it there and
// exits locked, so the runtime ends that thread; it never ends the main
// thread, though, and would park it for good in the stack's namespace,
// which then outlives the stack and is what /proc/<pid>/net shows (#5159).
func init() {
	runtime.LockOSThread()
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentos-enforcer:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("agentos-enforcer", flag.ContinueOnError)
	state := fs.String("state", "", "the enforcer's state directory (mode 0700, owned by this user)")
	cfgPath := fs.String("config", "", "the enforcer's configuration file (JSON)")
	provision := fs.String("provision", "", "first boot: provision enrolment with the case code in this file, then exit")
	pub := fs.Bool("channel-pub", false, "print the enforcer's channel public key (base64) for the core to pin, then exit")
	apSetup := fs.String("ap-setup", "", "with -provision: the setup network's Wi-Fi password, the sticker's, in this file")
	apPub := fs.Bool("ap-pub", false, "print the enforcer's SSH public key for the access points' authorized_keys, then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *state == "" {
		return errors.New("-state is required")
	}
	if os.Getuid() == 0 {
		return errors.New("refusing to run as root: run as the enforcer's own user with CAP_NET_ADMIN and CAP_NET_BIND_SERVICE")
	}
	if err := checkStateDir(*state); err != nil {
		return err
	}
	switch {
	case *provision != "":
		b, err := os.ReadFile(*provision)
		if err != nil {
			return err
		}
		if *apSetup == "" {
			return errors.New("-provision needs -ap-setup")
		}
		sb, err := os.ReadFile(*apSetup)
		if err != nil {
			return err
		}
		if err := checkSetup(strings.TrimSpace(string(sb))); err != nil {
			return err
		}
		if err := provisionState(*state, strings.TrimSpace(string(b))); err != nil {
			return err
		}
		return provisionAP(fileStore{path: filepath.Join(*state, fileAPKeys)}, strings.TrimSpace(string(sb)))
	case *apPub:
		s, err := apSSHKey(fileStore{path: filepath.Join(*state, fileAPSSH)}, nil)
		if err != nil {
			return err
		}
		fmt.Println(authorizedKey(s))
		return nil
	case *pub:
		k, err := channelKey(fileStore{path: filepath.Join(*state, fileChannelKey)}, nil)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
		return nil
	}
	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	cfg, err := parseConfig(b)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "", 0)
	if bootTime() == 0 {
		return errors.New("CLOCK_BOOTTIME unreadable")
	}
	dnsDir := filepath.Join(*state, "dns")
	if err := os.Mkdir(dnsDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	resolvers, err := dnsrun.New(cfg.Dnsmasq, dnsDir, func(s string) { logger.Print(s) })
	if err != nil {
		return err
	}
	d, err := open(cfg, *state, deps{
		DNS:     resolvers,
		MDNS:    mdns.Serve,
		Wake:    func(ctx context.Context, r *wol.Relay) error { return r.Serve(ctx) },
		Boot:    traffic.BootID,
		Offload: offload.Off,
		Served:  served,
		Elapsed: bootTime,
		Fire:    load.Loader{Bin: cfg.Nft},
		AP:      newPusher(cfg.Layout.APMgmt),
		Light:   newLogLight(logger),
		Radio:   noRadio{},
		Logf:    func(s string) { logger.Print(s) },
		Listen:  true,
	})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// A channel listener that stops for anything but a temporary error
	// (ServeChannel retries those) stops the daemon, so the service
	// manager restarts it rather than leave the channel down (#4755 item 5).
	chDown := make(chan error, 1)
	if d.ch != nil {
		ln, err := net.Listen("tcp", cfg.Channel.String())
		if err != nil {
			return err
		}
		defer ln.Close()
		go func() { chDown <- d.ServeChannel(ln) }()
	} else {
		logger.Print("channel: " + errNoCore.Error())
	}
	go func() {
		if err := d.ServeWake(ctx); err != nil && ctx.Err() == nil {
			logger.Print("wake: relay stopped: " + err.Error())
		}
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-chDown:
			return fmt.Errorf("channel listener stopped: %w", err)
		case err := <-d.freshStop:
			// The fresh byte-cap day is saved: the service manager starts
			// the daemon again, which reads it as any saved day (ENF-l-19).
			return err
		case <-t.C:
		case <-d.changed:
		}
		d.Tick(ctx)
	}
}

// noRadio is the radio host until ENF-l-b2 part b wires slice k's: every command
// and state read is refused, so the channel answers Failed.
type noRadio struct{}

func (noRadio) Do(string, wire.Verb, uint8) error { return errors.New("no radio host (ENF-l-b)") }
func (noRadio) State(string) ([]byte, error)      { return nil, errors.New("no radio host (ENF-l-b)") }

// logLight is the bulb until its driver lands (#4305): a change of
// colour goes to the enforcer's log. The alerts re-show the light on every
// change and each minute (Refresh); only a change is a line, so the log
// keeps the channel's record readable.
type logLight struct {
	l  *log.Logger
	st *lightState
}

type lightState struct {
	mu    sync.Mutex
	shown bool
	last  alert.Colour
}

func newLogLight(l *log.Logger) logLight { return logLight{l: l, st: &lightState{}} }

func (l logLight) Show(c alert.Colour) error {
	l.st.mu.Lock()
	defer l.st.mu.Unlock()
	if l.st.shown && l.st.last == c {
		return nil
	}
	l.st.shown, l.st.last = true, c
	l.l.Printf("light: %d", c)
	return nil
}
