// Package offload keeps the receive offloads that merge segments off on
// the enforcer's counted ports (ENF-cap-gro, #4610; NET-2 Byte caps,
// D-255).
//
// The byte caps count IP bytes as the kernel holds each packet
// (`skb->len`, nft ASSUMPTIONS ENF-cap-trip-c-1). A port that merges the
// segments it receives (GRO, LRO, hardware GRO) hands the firewall one
// packet with one IP header for several segments, so the count runs under
// the bytes that leave the WAN once the packet is split again: a few
// percent for full segments, up to about 1.7 times for minimum-size ones.
// Off turns those offloads off on a port and on every device its packets
// are received on first, and reads them back; the daemon holds a port
// whose features stay on at its caps (ASSUMPTIONS ENF-gro-1).
//
// It speaks the kernel's ethtool netlink family and reads links with
// rtnetlink, through the standard library's syscall package with
// golang.org/x/sys/unix's names for the kernel's numbers: no process and
// no unsafe memory of its own.
package offload

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Merging are the features under which one received packet can carry
// several segments: software GRO, LRO and hardware GRO. The other GRO
// features (rx-gro-list, rx-udp-gro-forwarding) only shape what software
// GRO does, and software GRO does not run on a device without rx-gro
// (ASSUMPTIONS ENF-gro-2).
var Merging = []string{"rx-gro", "rx-lro", "rx-gro-hw"}

// ErrStuck is a feature that stays as it was after Set asked to change
// it: the kernel or the driver holds it (a merging feature fixed on).
var ErrStuck = errors.New("offload: a feature stays as it was")

// Off turns every Merging feature off on each port and on the devices
// under it (a VLAN's or macvlan's parent, a bond's or bridge's members,
// walked down to the hardware, each lower device before the ones on it),
// then reads each back. It returns an error naming every port that is
// missing, unreadable, still merging or on a parent in another
// namespace; a device already off is only read, so a repeat call changes
// nothing.
func Off(ports ...string) error {
	devs, err := under(ports)
	if err != nil {
		return err
	}
	off := map[string]bool{}
	for _, f := range Merging {
		off[f] = false
	}
	var errs []error
	for _, d := range devs {
		if err := Set(d, off); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Set asks the kernel to turn each named feature of dev on (true) or off
// (false), changing only those that differ, and reads them back. It
// returns ErrStuck, wrapped with the features that did not take, when one
// stays as it was.
func Set(dev string, want map[string]bool) error {
	c, err := dial()
	if err != nil {
		return fmt.Errorf("offload: %s: %w", dev, err)
	}
	defer c.close()
	active, err := c.active(dev)
	if err != nil {
		return fmt.Errorf("offload: %s: %w", dev, err)
	}
	change := map[string]bool{}
	for f, on := range want {
		if active[f] != on {
			change[f] = on
		}
	}
	if len(change) == 0 {
		return nil
	}
	if err := c.set(dev, change); err != nil {
		return fmt.Errorf("offload: %s: %w", dev, err)
	}
	if active, err = c.active(dev); err != nil {
		return fmt.Errorf("offload: %s: %w", dev, err)
	}
	var stuck []string
	for f, on := range want {
		if active[f] != on {
			stuck = append(stuck, fmt.Sprintf("%s %s", f, onOff(active[f])))
		}
	}
	if len(stuck) > 0 {
		slices.Sort(stuck)
		return fmt.Errorf("%w: %s: %s", ErrStuck, dev, strings.Join(stuck, ", "))
	}
	return nil
}

// features is dev's active features, by the kernel's names, each true.
func features(dev string) (map[string]bool, error) {
	c, err := dial()
	if err != nil {
		return nil, fmt.Errorf("offload: %s: %w", dev, err)
	}
	defer c.close()
	a, err := c.active(dev)
	if err != nil {
		return nil, fmt.Errorf("offload: %s: %w", dev, err)
	}
	return a, nil
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
