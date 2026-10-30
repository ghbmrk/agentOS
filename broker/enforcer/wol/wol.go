// Package wol is the enforcer's Wake-on-LAN relay (SPEC NET-2 Segments,
// HW-11; briefs/ENF.md slice f, decision 5): the core's segment is its own
// broadcast domain, so the core wakes a paired helper machine only through
// the enforcer, which relays the core's magic packet to a paired machine
// and to nothing else.
//
// The relay hears only the core's interface. A packet is relayed only if
// it is exactly a magic packet (six 0xff bytes, then the target's hardware
// address sixteen times, optionally a six-byte SecureOn password) for a
// machine on its list, and then only as a broadcast on that machine's own
// network, at most once per WakeInterval per machine.
//
// It is enforcer code: it imports the standard library and the enforcer's
// nft package only (broker/daemon/arc2_test.go). Its assumptions are in
// ASSUMPTIONS.md.
package wol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
)

var ErrRelay = errors.New("wol: relay refused")

// WakeInterval is the shortest time between two wakes of one machine.
const WakeInterval = 2 * time.Second

// Machine is one paired machine: its hardware address and the interface
// of the network it is on.
type Machine struct {
	MAC   net.HardwareAddr
	Iface string
}

// Relay relays the core's magic packets to its machines.
type Relay struct {
	core     string
	machines []Machine

	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
}

// New is the relay for the core's interface on l and machines. A machine
// may be on the Owner or the Household network or on its own Devices VLAN,
// never on the core's, the edge's, the Guests', the admin port, the WAN or
// the access point's management interface; its address must be one
// machine's (unicast, not all zeros), each on the list once.
func New(l nft.Layout, machines []Machine) (*Relay, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	r := &Relay{core: l.Core, last: map[string]time.Time{}, now: time.Now}
	for _, m := range machines {
		vlan, isDev := strings.CutPrefix(m.Iface, l.Trunk+".")
		_, okVLAN := nft.VLAN("vlan" + vlan)
		if m.Iface != l.Owner && m.Iface != l.Household && !(isDev && okVLAN) {
			return nil, fmt.Errorf("%w: no wake on %q", ErrRelay, m.Iface)
		}
		if len(m.MAC) != 6 || m.MAC[0]&1 != 0 || bytes.Equal(m.MAC, make([]byte, 6)) {
			return nil, fmt.Errorf("%w: hardware address %v", ErrRelay, m.MAC)
		}
		if r.find(m.MAC) != nil {
			return nil, fmt.Errorf("%w: %v twice", ErrRelay, m.MAC)
		}
		r.machines = append(r.machines, Machine{MAC: slices.Clone(m.MAC), Iface: m.Iface})
	}
	return r, nil
}

func (r *Relay) find(mac net.HardwareAddr) *Machine {
	for i := range r.machines {
		if bytes.Equal(r.machines[i].MAC, mac) {
			return &r.machines[i]
		}
	}
	return nil
}

// Target is the machine pkt wakes, or nil: nil for anything that is not
// exactly a magic packet for a machine on the list, or for a machine woken
// less than WakeInterval ago.
func (r *Relay) Target(pkt []byte) *Machine {
	if len(pkt) != 102 && len(pkt) != 108 {
		return nil
	}
	if !bytes.Equal(pkt[:6], bytes.Repeat([]byte{0xff}, 6)) {
		return nil
	}
	mac := pkt[6:12]
	if !bytes.Equal(pkt[6:102], bytes.Repeat(mac, 16)) {
		return nil
	}
	m := r.find(mac)
	if m == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(m.MAC)
	if t, ok := r.last[key]; ok && r.now().Sub(t) < WakeInterval {
		return nil
	}
	r.last[key] = r.now()
	return m
}

// Serve relays until ctx ends.
func (r *Relay) Serve(ctx context.Context) error {
	in, err := listen(r.core, false)
	if err != nil {
		return err
	}
	outs := map[string]*net.UDPConn{}
	closeAll := func() {
		in.Close()
		for _, c := range outs {
			c.Close()
		}
	}
	for _, m := range r.machines {
		if outs[m.Iface] != nil {
			continue
		}
		c, err := listen(m.Iface, true)
		if err != nil {
			closeAll()
			return err
		}
		outs[m.Iface] = c
	}
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	bcast := &net.UDPAddr{IP: net.IPv4bcast, Port: nft.WoLPort}
	buf := make([]byte, 109)
	for {
		n, _, err := in.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		if m := r.Target(buf[:n]); m != nil {
			outs[m.Iface].WriteToUDP(buf[:n], bcast)
		}
	}
}

// listen is a socket bound to iface (SO_BINDTODEVICE) at the Wake-on-LAN
// port: the core's hears only the core's segment, a sender's broadcasts go
// only to its own network.
func listen(iface string, send bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			s := int(fd)
			serr = errors.Join(syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1), syscall.BindToDevice(s, iface))
			if send {
				serr = errors.Join(serr, syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1))
			}
		})
		return errors.Join(err, serr)
	}}
	port := nft.WoLPort
	if send {
		port = 0
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrRelay, iface, err)
	}
	return pc.(*net.UDPConn), nil
}
