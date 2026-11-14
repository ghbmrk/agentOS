// Command agentos-port1 is the owner page's root step (HW12-port1-set; CH-9, HW-12): run as
// root before each start of agentos-localui.service (its ExecStartPre=+), it chooses port 1 as
// the page does, opens the page's ports in the inbound firewall on it alone, writes its name to
// -port1-file for the page, and exits. It was agentos-localui's -admit-port1 step; it is its
// own binary so that the trusted core counts exactly what root runs here and none of the page's
// import graph runs as root (KEY-9-reach-inbound-wiring, #5678; tools/trusted_core.txt).
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard/port1"
)

func main() {
	var iface, file string
	flag.StringVar(&iface, "iface", "", "port 1's interface, the core's cable to the enforcer; empty: the one fixed PCI Ethernet port (port1.Port1), and none if two or more")
	flag.StringVar(&file, "port1-file", "", "where the admitted port 1's name goes for the page (agentos-localui -port1-file)")
	flag.Parse()
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p, err := admitPort1("/sys", iface, file, runNft, func() bool { return pause(ctx, recheck) })
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("the page's ports are open on port 1, %s, and nowhere else", p)
}

// recheck is how long port 1 must stay the same before it is admitted;
// the page's watcher reads sysfs again at the same period.
const recheck = 10 * time.Second

// pause waits d, reporting false if ctx ends first.
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// admitPort1 is the page unit's root step (HW12-port1-set; CH-9, HW-12):
// port 1 is iface, or port1.Settled when iface is empty, and must be a
// wired link (port1.Wired); nft makes it the inbound table's page set's
// only element, and its name goes to file for the page. The unit's stop
// empties the set again, so a failure here, or a page that is not
// running, leaves the page's ports dropped on every link.
func admitPort1(sys, iface, file string, nft func(script string) error, wait func() bool) (string, error) {
	if file == "" {
		return "", errors.New("agentos-port1 needs -port1-file")
	}
	p := iface
	if p == "" {
		var err error
		if p, err = port1.Settled(sys, wait); err != nil {
			return "", err
		}
	}
	if err := port1.Wired(sys, p); err != nil {
		return "", err
	}
	script, err := port1.Admit(p)
	if err != nil {
		return "", err
	}
	if err := nft(script); err != nil {
		return "", errors.New("could not open the page's ports on port 1 " + p + " in the inbound firewall: " + err.Error())
	}
	return p, port1.Write(file, p)
}

// runNft loads script with one nft -f, a single transaction: a fixed
// absolute binary, an empty environment, the script on stdin
// (ASSUMPTIONS PORT1-exec-1).
func runNft(script string) error {
	cmd := exec.Command("/usr/sbin/nft", "-f", "-")
	cmd.Env = []string{}
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(out)) + " (" + err.Error() + ")")
	}
	return nil
}
