package nft

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// REQ: NET-3

// TestForwardedAckLeasesNothing: a guest has an internet host answer it
// from port 67 with a DHCPACK-shaped reply that leases the first host's
// address to the guest's hardware address (#5687, L3 and Security
// verdicts). The reply is forwarded out of the segment's interface; the
// enforcer's lease copies must not learn it, so the guest's ARP reply for
// that address is still dropped and the first host's flow lives. A mutant
// without the ownAck guard loaded in the same test learns the lease and
// moves the entry, so the harness sees the attack.
func TestForwardedAckLeasesNothing(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d := cutPolicy()
	seg := "guest"
	h.share(seg)
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	ifc := segIfc(seg)
	a, b := h.hosts[seg], h.hosts[seg+"2"]
	macA, err := net.ParseMAC(h.mac(a, "eth0"))
	if err != nil {
		t.Fatal(err)
	}
	macB, err := net.ParseMAC(h.mac(b, "eth0"))
	if err != nil {
		t.Fatal(err)
	}
	victim := segAddr(seg, 0)
	h.echo("isp", netOther)

	// The internet host answers any datagram to its port 67 with the
	// forged ACK (lease time LeaseTimeout, the last band).
	ack := make([]byte, 300)
	ack[0], ack[1], ack[2] = 2, 1, 6
	copy(ack[16:20], net.ParseIP(victim).To4())
	copy(ack[28:34], macB)
	binary.BigEndian.PutUint32(ack[236:], 0x63825363)
	copy(ack[240:], []byte{0x35, 1, 5, 0x36, 4, 1, 2, 3, 4, 0x33, 4})
	binary.BigEndian.PutUint32(ack[251:], LeaseTimeout)
	ack[255] = 0xff
	const forgePort = "9125"
	isp := h.hosts["isp"]
	h.in(isp, "nft", "add table ip forge; add chain ip forge pre { type nat hook prerouting priority dstnat; }; "+
		"add rule ip forge pre udp dport 67 dnat to "+netOther+":"+forgePort)
	within(t, isp, func() {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(netOther, forgePort))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 1500)
			for {
				_, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				pc.WriteTo(ack, from)
			}
		}()
	})

	// forge has the guest fetch the forged ACK through the enforcer, then
	// send its ARP reply naming the first host's address.
	forge := func(why, to string) {
		t.Helper()
		within(t, b, func() {
			c, err := (&net.Dialer{LocalAddr: &net.UDPAddr{Port: 68}}).Dial("udp", net.JoinHostPort(to, "67"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write([]byte("ask"))
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(make([]byte, 1500)); err != nil {
				t.Fatalf("%s: the forged ACK did not reach the guest, so the test shows nothing: %v", why, err)
			}
		})
		h.frame(b, 0x0806, bcast, arp(2, macB, victim, enfAddr(seg)))
		time.Sleep(200 * time.Millisecond)
	}
	// nft lists a raw-payload key as hex, each field without leading zeros.
	forged := fmt.Sprintf("%#x . %#x", binary.BigEndian.Uint32(net.ParseIP(victim).To4()),
		binary.BigEndian.Uint64(append([]byte{0, 0}, macB...)))
	learnt := func() bool {
		return strings.Contains(run(t, "nft", "list", "set", "netdev", NeighTable, LeaseSet(nftSeg(seg))), forged)
	}

	load := func(text string) *flow {
		t.Helper()
		h.load(withDrops(t, d, text))
		h.fillSets()
		// An ARP reply within locktime of an entry's last change does
		// not move it; the test does not wait for that.
		if err := os.WriteFile("/proc/sys/net/ipv4/neigh/"+ifc+"/locktime", []byte("0"), 0); err != nil {
			t.Fatal(err)
		}
		f := h.udpFlow(seg, netOther, 0, "first")
		if !f.heard("first") {
			t.Fatal("the first host's flow is not answered")
		}
		return f
	}

	f := load(text)
	forge("guarded", netOther)
	if learnt() {
		t.Errorf("the netdev lease copy learnt %s from a forwarded ACK", forged)
	}
	if got := h.neighbour(ifc, victim); got != macA.String() {
		t.Errorf("the enforcer's entry for %s names %q, want the first host's %s", victim, got, macA)
	}
	f.say("after")
	if !f.heard("after") {
		t.Error("the first host's flow stopped after the forged ACK")
	}

	// The mutant: ack_<seg> reads every ACK-shaped packet, marked or not.
	guard := "meta mark and " + ownAck + " != 0 "
	if n := strings.Count(text, guard); n != len(leaseBands())*len(segments(fixtureLayout())) {
		t.Fatalf("the guard is on %d lines, want one per band per shared segment", n)
	}
	load(strings.ReplaceAll(text, guard, ""))
	// Another internet address, so the guest's datagram opens a new
	// connection rather than reusing the guarded run's.
	forge("mutant", netAllow)
	if !learnt() {
		t.Errorf("without the guard, the lease copy did not learn %s: the test cannot see the attack", forged)
	}
	if got := h.neighbour(ifc, victim); got != macB.String() {
		t.Errorf("without the guard, the entry for %s names %q, want the guest's %s: the test cannot see the attack", victim, got, macB)
	}
}
