// Command agentos-ap is the image's access point loader (P2-1): it serves
// the sticker's setup network (§8.1 step 4; CH-7, HW-10) on the box's
// radio, so a phone can reach the Wi-Fi page at 10.42.0.1.
//
// It drives the access point only through localui.APLoader (DEV-net-h):
// at start it brings down every wireless interface, which also takes back
// one a dead loader left exempt from the inbound drop, before anything
// brings one up or joins a network on it. It then brings the access point
// up on -iface with the setup network, unless the Owner Card step has
// confirmed or the box is owned, when it burns the setup network instead
// (firstboot.SetupNetwork). At shutdown, or when hostapd or dnsmasq dies,
// it brings the access point down; the unit restarts it after a death.
//
// It runs as root: it loads nftables, starts the exempt unit and gives the
// radio its address. It reads the page's latch, which the page can write,
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
	"path/filepath"
	"slices"
	"syscall"

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
	ap := &localui.Hostapd{Dir: dir}
	l := &localui.APLoader{AP: ap, Host: localui.ExecHost{}}
	if err := run(ctx, c, l, ap.Exited); err != nil {
		log.Fatalf("agentos-ap: %v", err)
	}
}

// run brings every radio down, serves the setup network on c.Iface if the
// box still has one, and holds it until ctx ends or exited fires.
func run(ctx context.Context, c config, l *localui.APLoader, exited func() <-chan struct{}) error {
	radios, err := wireless(c.SysClassNet)
	if err != nil {
		return err
	}
	if len(radios) == 0 {
		log.Print("agentos-ap: no wireless interface; serving nothing")
		<-ctx.Done()
		return nil
	}
	if err := l.Start(ctx, radios...); err != nil {
		return err
	}
	if !slices.Contains(radios, c.Iface) {
		log.Printf("agentos-ap: no wireless interface %s; every radio is down and none serves", c.Iface)
		<-ctx.Done()
		return nil
	}
	latch, err := readLatch(c.Latch)
	if err != nil {
		return err
	}
	_, err = os.Lstat(c.OwnerState)
	owned := !errors.Is(err, os.ErrNotExist)
	n, err := firstboot.SetupNetwork(latch, owned, change.FileStore{Path: c.Setup})
	if err != nil {
		return err
	}
	if n == nil {
		log.Print("agentos-ap: no setup network to serve")
		<-ctx.Done()
		return nil
	}
	if err := l.Up(ctx, localui.APConfig{Iface: c.Iface, Addr: c.Addr, SSID: n.SSID, Password: n.Password}); err != nil {
		return err
	}
	log.Printf("agentos-ap: serving the setup network on %s", c.Iface)
	select {
	case <-ctx.Done():
		return l.Down(context.Background())
	case <-exited():
		return errors.Join(errors.New("an access point child exited"), l.Down(context.Background()))
	}
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
