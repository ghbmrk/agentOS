// Command agentos-ap is the image's access point loader (P2-1): it serves
// the sticker's setup network (§8.1 step 4; CH-7, HW-10) on the box's
// radio, so a phone can reach the Wi-Fi page at 10.42.0.1.
//
// It drives the access point only through localui.APLoader (DEV-net-h):
// at start it brings down every wireless interface, which also takes back
// one a dead loader left exempt from the inbound drop, before anything
// brings one up or joins a network on it. A radio that appears late (its
// driver loads after the loader starts) is waited for. It then serves on
// -iface the setup network until the Owner Card step confirms or the box
// is owned, and from then on the card's network (#1185), which the page
// reports through agentosd before the confirm latches (-ap-net). It reads
// the latch, the owner state and both files again every -poll. At the
// confirm it brings the access point down, burns the setup network
// (firstboot.SetupNetwork), and brings it up with the card's network:
// Down then Up, never Rekey, so the phone rejoins with the card's Wi-Fi QR
// code. Both networks are WPA3-SAE only (CH-7). A box with neither serves
// nothing until it has one. At shutdown, or when hostapd or dnsmasq dies,
// it brings the access point down; the unit restarts it after a death.
//
// It runs as root: it loads nftables, starts the exempt unit and gives the
// radio its address. hostapd runs as its own user, agentos-hostapd, with
// NET_ADMIN and NET_RAW only (#1426): as root it would pass egress's uid-0
// broker check. It reads the page's latch, which the page can write,
// without following a link and only so far (readLatch).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localui"
)

type config struct {
	// Iface is the radio that serves the setup network.
	Iface string
	// Addr is the box's address on it, with the subnet's length.
	Addr netip.Prefix
	// Latch is the Owner Card step's latch (the page's file); Setup the
	// setup network (root's); OwnerState agentosd's owner state, whose
	// presence means setup has finished.
	Latch, Setup, OwnerState string
	// SysClassNet lists the interfaces; a wireless one has phy80211.
	SysClassNet string
	// APNet is the card's network, which the page reports through
	// agentosd before the confirm (#1185); root's, mode 0600.
	APNet string
	// Poll is how often it looks for a late radio and, while it serves,
	// for the confirm or the owner state.
	Poll time.Duration
}

// maxLatch bounds what is read of the latch; the page writes a few
// fields.
const maxLatch = 64 << 10

func main() {
	var c config
	var addr, dir string
	flag.StringVar(&c.Iface, "iface", "wlan0", "the radio that serves the setup network")
	flag.StringVar(&addr, "addr", "10.42.0.1/24", "my address on the access point, with the subnet's length")
	flag.StringVar(&c.Latch, "card-latch", "/var/lib/agentos-localui/card-latch.json", "the Owner Card step's latch (the page's)")
	flag.StringVar(&c.Setup, "setup-net", claim.SetupNetPath, "the setup network the seller sealed (HW-10)")
	flag.StringVar(&c.OwnerState, "owner-state", "/var/lib/agentos/owner.json", "agentosd's owner state; present once setup has finished")
	flag.StringVar(&c.SysClassNet, "sys-class-net", "/sys/class/net", "where the kernel lists network interfaces")
	flag.StringVar(&c.APNet, "ap-net", apnet.Path, "the card's Wi-Fi network, served once the card is confirmed")
	flag.DurationVar(&c.Poll, "poll", 2*time.Second, "how often I look for a late radio and, while serving, for the confirm")
	flag.StringVar(&dir, "dir", "/run/agentos-ap", "where hostapd's and dnsmasq's configuration lives while the access point runs")
	flag.Parse()
	log.SetFlags(0)
	p, err := netip.ParsePrefix(addr)
	if err != nil {
		log.Fatalf("agentos-ap: -addr: %v", err)
	}
	c.Addr = p
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ap, err := newHostapd(dir, user.Lookup)
	if err != nil {
		log.Fatalf("agentos-ap: %v", err)
	}
	l := &localui.APLoader{AP: ap, Host: localui.ExecHost{}}
	if err := run(ctx, c, l, ap.Exited); err != nil {
		log.Fatalf("agentos-ap: %v", err)
	}
}

// hostapdUser is the user hostapd runs as; the image's sysusers.d creates
// it.
const hostapdUser = "agentos-hostapd"

// newHostapd is the access point with hostapd run as hostapdUser, looked
// up at each start (no fixed uid). It fails closed: without the user, or
// with a root uid or gid, nothing serves.
func newHostapd(dir string, lookup func(string) (*user.User, error)) (*localui.Hostapd, error) {
	u, err := lookup(hostapdUser)
	if err != nil {
		return nil, fmt.Errorf("hostapd's user: %w", err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("hostapd's user: uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("hostapd's user: gid %q: %w", u.Gid, err)
	}
	if uid == 0 || gid == 0 {
		return nil, fmt.Errorf("hostapd's user %s is root", hostapdUser)
	}
	return &localui.Hostapd{Dir: dir, User: &localui.APUser{UID: uint32(uid), GID: uint32(gid)}}, nil
}

// run brings every radio down, waits for c.Iface if it has not appeared,
// and then serves on it whichever network the box should (want) until ctx
// ends or exited fires. It looks again every c.Poll: a change of network
// brings the access point down before the next comes up (#1185), so the
// setup network is off the air, and burned, before the card's appears.
//
// A card's network whose Up fails, or whose child dies before it has
// served settlePolls looks, is counted against that version of the file
// (apnet.RecordUpFailure), across the restarts that follow, for agentosd
// to tell the owner past the bound (#1525); one that settles clears the
// count. A failure never brings any other network up: the next run
// serves what the file holds, or nothing.
func run(ctx context.Context, c config, l *localui.APLoader, exited func() <-chan struct{}) error {
	if err := waitForIface(ctx, c, l); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	var up *served // what the access point serves; nil while it is down
	down := func() error {
		up = nil
		return l.Down(context.Background())
	}
	tick := time.NewTicker(c.Poll)
	defer tick.Stop()
	logged := false
	settled := 0 // looks the card's network has served since it came up
	failed := func(w *served) {
		if w == nil || w.name != cardNetwork {
			return
		}
		if _, err := apnet.RecordUpFailure(c.APNet); err != nil {
			log.Printf("agentos-ap: counting the card's network failure: %v", err)
		}
	}
	for {
		w, err := want(c, l, &up)
		if err != nil {
			if up != nil {
				err = errors.Join(err, down())
			}
			return err
		}
		if w != up && (w == nil || up == nil || *w != *up) {
			if up != nil {
				if err := down(); err != nil {
					return err
				}
			}
			if w != nil {
				if err := l.Up(ctx, localui.APConfig{Iface: c.Iface, Addr: c.Addr, SSID: w.SSID, Password: w.Password}); err != nil {
					failed(w)
					return errors.Join(err, l.Down(context.Background()))
				}
				up = w
				settled = 0
				log.Printf("agentos-ap: serving the %s on %s", w.name, c.Iface)
			}
			logged = false
		}
		if up == nil && !logged {
			log.Print("agentos-ap: no network to serve yet")
			logged = true
		}
		var gone <-chan struct{}
		if up != nil {
			gone = exited()
		}
		select {
		case <-ctx.Done():
			if up == nil {
				return nil
			}
			return down()
		case <-gone:
			if settled < settlePolls {
				failed(up)
			}
			return errors.Join(errors.New("an access point child exited"), down())
		case <-tick.C:
			if up != nil && up.name == cardNetwork && settled < settlePolls {
				if settled++; settled == settlePolls {
					if err := apnet.ClearUpFailures(c.APNet); err != nil {
						log.Printf("agentos-ap: clearing the card's network failures: %v", err)
					}
				}
			}
		}
	}
}

// cardNetwork names the card's network in served; settlePolls is how
// many looks it serves before its failures are cleared (#1525).
const (
	cardNetwork = "card's network"
	settlePolls = 15
)

// served is a network the access point serves; name says which, for the
// log, which never holds the password (ARC-1).
type served struct {
	name, SSID, Password string
}

// want is the network the box should serve: the sticker's setup network
// until the Owner Card step confirms or the box is owned, then the card's
// (#1185), which the page reported before the confirm latched. Burning
// the setup network brings the access point down first (downFirst), and
// clears *up to say so. A box with neither serves nothing.
func want(c config, l *localui.APLoader, up **served) (*served, error) {
	n, err := setupNetwork(c, downFirst{FileStore: change.FileStore{Path: c.Setup}, down: func() error {
		*up = nil
		return l.Down(context.Background())
	}})
	if err != nil {
		return nil, err
	}
	if n != nil {
		return &served{name: "setup network", SSID: n.SSID, Password: n.Password}, nil
	}
	owned, err := ownedOrConfirmed(c)
	if err != nil || !owned {
		return nil, err
	}
	b, err := os.ReadFile(c.APNet)
	if errors.Is(err, os.ErrNotExist) || err == nil && len(b) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("card network: %w", err)
	}
	cn, err := apnet.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("card network: %w", err)
	}
	return &served{name: cardNetwork, SSID: cn.SSID, Password: cn.Password}, nil
}

// ownedOrConfirmed says whether the box is owned or its card confirmed,
// read as setupNetwork reads them.
func ownedOrConfirmed(c config) (bool, error) {
	if owned(c) {
		return true, nil
	}
	latch, err := readLatch(c.Latch)
	if err != nil {
		return false, err
	}
	return firstboot.CardConfirmed(latch)
}

// waitForIface brings down every radio and waits for c.Iface to be one,
// bringing down each radio that appears meanwhile, until ctx ends.
func waitForIface(ctx context.Context, c config, l *localui.APLoader) error {
	var down []string
	logged := false
	for {
		radios, err := wireless(c.SysClassNet)
		if err != nil {
			return err
		}
		if fresh := slices.DeleteFunc(slices.Clone(radios), func(r string) bool { return slices.Contains(down, r) }); len(fresh) > 0 {
			if err := l.Start(ctx, fresh...); err != nil {
				return err
			}
			down = append(down, fresh...)
		}
		if slices.Contains(radios, c.Iface) {
			return nil
		}
		if !logged {
			log.Printf("agentos-ap: no wireless interface %s yet; every radio is down and none serves", c.Iface)
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(c.Poll):
		}
	}
}

// setupNetwork reads the latch and the owner state and asks
// firstboot.SetupNetwork, which burns through setup on a confirmed or
// owned box. An owner state it cannot stat counts as owned.
func setupNetwork(c config, setup firstboot.Store) (*claim.SetupNet, error) {
	latch, err := readLatch(c.Latch)
	if err != nil {
		return nil, err
	}
	return firstboot.SetupNetwork(latch, owned(c), setup)
}

// owned says whether agentosd's owner state is there. One it cannot stat
// counts as owned.
func owned(c config) bool {
	_, err := os.Lstat(c.OwnerState)
	return !errors.Is(err, os.ErrNotExist)
}

// downFirst is the setup file, whose burn first brings the access point
// down.
type downFirst struct {
	change.FileStore
	down func() error
}

func (d downFirst) Save(b []byte) error {
	if err := d.down(); err != nil {
		return err
	}
	return d.FileStore.Save(b)
}

// wireless lists the interfaces in sysClassNet that have a radio, sorted.
func wireless(sysClassNet string) ([]string, error) {
	ents, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(sysClassNet, e.Name(), "phy80211")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// readLatch reads the latch, nil when there is none. It refuses a link,
// anything but a regular file (a FIFO would block), and more than maxLatch
// bytes: the page, which this root process does not trust, writes it.
func readLatch(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("card latch: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("card latch: not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxLatch+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxLatch {
		return nil, errors.New("card latch: too large")
	}
	return b, nil
}
