package nft

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// The netns harness, for caps_netns_test.go: that file is in package
// nft_test so it can drive broker/enforcer/traffic's counter, which
// imports this package, against the real ruleset.

type Home = home

func InNetns(t *testing.T) bool { return inNetns(t) }

// Build is the fixture home with the core given IPv6 as well, where the
// kernel has it.
func Build(t *testing.T) *Home {
	h := build(t)
	if h.v6 {
		h.seg6("core")
	}
	return h
}

func FixtureLayout() Layout                                      { return fixtureLayout() }
func FixturePolicy() policy.Document                             { return fixturePolicy() }
func (h *home) V6() bool                                         { return h.v6 }
func (h *home) Counter(n string) int                             { return h.counter(n) }
func (h *home) Answer(d policy.Document, set, name, addr string) { h.answer(d, set, name, addr) }

const (
	NetCore   = netCore
	NetOther  = netOther
	NetAllow  = netAllow
	NetDoH    = netDoH
	Net6Other = net6Other
)

func loader(t *testing.T) load.Loader {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	return load.Loader{Bin: nftBin}
}

// List is the running table's listing.
func (h *home) List() []byte {
	b, err := loader(h.t).List(context.Background(), Table)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

// Load is a full load of text through the loader.
func (h *home) Load(text string) { h.load(text) }

// Update applies a drop update through the loader.
func (h *home) Update(text string) {
	h.t.Helper()
	if err := loader(h.t).Update(context.Background(), text); err != nil {
		h.t.Fatal(err)
	}
}

// echoUDP is the port of the echo SendUDP's datagrams go to, which the
// ISP's namespace answers from the address each was sent to (EchoUDP):
// the fixture's echo listeners are unbound, so their replies leave from
// the ISP router's own address and match no connection.
const echoUDP = "9123"

// EchoUDP answers datagrams to addr's echo port, from addr.
func (h *home) EchoUDP(addr string) {
	within(h.t, h.hosts["isp"], func() {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(addr, echoUDP))
		if err != nil {
			h.t.Fatal(err)
		}
		h.t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				pc.WriteTo(buf[:n], from)
			}
		}()
	})
}

// SendUDP sends one datagram of n payload bytes from host from to addr's
// echo port (EchoUDP) and reports whether the echo came back: the
// datagram crossed the enforcer.
func (h *home) SendUDP(from, addr string, n int) bool {
	ok := false
	within(h.t, h.hosts[from], func() {
		c, err := net.Dial("udp", net.JoinHostPort(addr, echoUDP))
		if err != nil {
			h.t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(probeWait))
		if _, err := c.Write(make([]byte, n)); err != nil {
			return
		}
		buf := make([]byte, 2048)
		_, err = c.Read(buf)
		ok = err == nil
	})
	return ok
}

// Serve listens on addr:port in the ISP's namespace and gives each
// connection to f.
func (h *home) Serve(addr string, port int, f func(net.Conn)) {
	within(h.t, h.hosts["isp"], func() {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err != nil {
			h.t.Fatal(err)
		}
		h.t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); f(c) }()
			}
		}()
	})
}

// Dial opens a TCP connection from host from to addr:port, runs f on it
// until wait passes, and returns what f returned.
func (h *home) Dial(from, addr string, port int, wait time.Duration, f func(net.Conn) int) int {
	n := -1
	within(h.t, h.hosts[from], func() {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), probeWait)
		if err != nil {
			h.t.Fatalf("%s dials %s:%d: %v", from, addr, port, err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(wait))
		n = f(c)
	})
	return n
}
