package nft

// REQ: NET-5, NET-3, NET-2

import (
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLinesBound (#4432, #4762, P4): every refusal, and every connection a
// box starts to a device, goes to its prefix's logged chain, which counts
// it, logs it only within its interface's bucket and gives the verdict
// whether or not it logged: a refused packet from a device is counted on
// the device's counter and its destination's too. No other rule writes a
// line. Catches a line without a bound, a bound that skips the count or
// the verdict (an accept a bucket refuses), and a device whose refusals or
// their destinations are not counted.
func TestLinesBound(t *testing.T) {
	text, err := Compile(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	text = withDrops(t, fixturePolicy(), text) // a cap's refusals are in the drop state
	cs := chains(text)
	limit := " limit rate " + strconv.Itoa(LineRate) + "/minute burst " + strconv.Itoa(LineBurst) + " packets }"
	for _, p := range slices.Concat(refusals, accepts) {
		key := map[string]string{"drop": "iif", "accept": "oif"}[p.verdict]
		want := []string{`counter name "` + p.counter + `"`}
		if p.verdict == "drop" {
			want = append(want, "iifname vmap @refused")
		}
		want = append(want, "update @"+lines(p.prefix)+" { "+key+limit+` counter name "`+LogLines+`" log prefix "`+p.prefix+`"`, p.verdict)
		if got := cs[logged(p.prefix)]; !slices.Equal(got, want) {
			t.Errorf("chain %s:\n%q\nwant\n%q", logged(p.prefix), got, want)
		}
		decl := "set " + lines(p.prefix) + " {\n\t\ttypeof " + key + ";\n\t\tsize " + strconv.Itoa(LineSize) + ";\n\t\tflags dynamic,timeout;\n\t\ttimeout " + secs(LineIdle) + ";\n\t}"
		if !strings.Contains(text, decl) {
			t.Errorf("no %q", decl)
		}
		if !strings.Contains(text, "goto "+logged(p.prefix)) {
			t.Errorf("nothing goes to %s", logged(p.prefix))
		}
	}
	// Only the logged chains write a line, and a live rule never logs:
	// only a related packet's first form refuses with a line.
	for name, rs := range cs {
		for _, r := range rs {
			if strings.Contains(r, "log ") && !strings.HasPrefix(name, "log_") {
				t.Errorf("chain %s writes a line outside a logged chain: %s", name, r)
			}
		}
	}
	for _, r := range append(cs[live("forward")], cs[live("people")]...) {
		if strings.Contains(r, "goto log_") && !strings.HasPrefix(r, "ct state related ") {
			t.Errorf("a live rule logs: %s", r)
		}
	}
	// The boxes' connections to devices are logged, and accepted, there.
	for _, r := range cs["forward"] {
		if strings.Contains(r, `oifname "ap0.`) && (strings.HasPrefix(r, `iifname "edge0"`) || strings.HasPrefix(r, `iifname "core0"`)) &&
			!regexp.MustCompile(` goto log_(edge_dev|core_dev|core_stream)$`).MatchString(r) {
			t.Errorf("a box's connection to a device is not logged: %s", r)
		}
	}
	// Every device, isolated or not, counts its refusals and where.
	var elems []string
	for _, v := range []int{101, 102, 103, 104, 105, 106, 107, 108, 109} {
		elems = append(elems, strconv.Quote(fixtureLayout().deviceIface(v))+" : jump "+trafficChain(v, "refused"))
		want := []string{`counter name "` + TrafficRefused(v) + `"`, "update @" + RefusedSet(v, false) + " { ip daddr counter }", "update @" + RefusedSet(v, true) + " { ip6 daddr counter }"}
		if got := cs[trafficChain(v, "refused")]; !slices.Equal(got, want) {
			t.Errorf("chain %s:\n%q\nwant\n%q", trafficChain(v, "refused"), got, want)
		}
		for _, v6 := range []bool{false, true} {
			decl := "set " + RefusedSet(v, v6) + " {\n\t\ttype " + map[bool]string{false: "ipv4_addr", true: "ipv6_addr"}[v6] + ";\n\t\tsize " + strconv.Itoa(RefusedSize) + ";\n\t\tflags dynamic,timeout;\n\t\ttimeout 1d;\n\t}"
			if !strings.Contains(text, decl) {
				t.Errorf("no %q", decl)
			}
		}
		if !strings.Contains(text, "counter "+TrafficRefused(v)+" { }") {
			t.Errorf("no counter %s", TrafficRefused(v))
		}
	}
	if !strings.Contains(text, "map refused {\n\t\ttype ifname : verdict;\n\t\telements = { "+strings.Join(elems, ", ")+" }\n\t}") {
		t.Error("the refused map does not reach every device's chain")
	}
	none := fixturePolicy()
	none.Devices, none.Pairs = nil, nil
	text, err = Compile(none, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "map refused {\n\t\ttype ifname : verdict;\n\t}") {
		t.Error("with no devices the refused map is not empty")
	}
}

// TestLinesFloodBound (#4432, #4762, NET-5, P4): a device flooding refused
// packets, the internet flooding the enforcer's WAN, and the edge opening
// connection after connection to a device write at most their buckets'
// lines, while the counters move by every packet and every connection is
// accepted; another device's lines still log, from a bucket of their own,
// for the flooding box too (#4842).
// The kernel log is unreadable from a test namespace, so the lines are
// read from log_lines, the counter of the rule that writes them. Catches a
// line per packet or per connection (a box or a device fills the
// journal), a bound that loses counts, and one that refuses a connection.
func TestLinesFloodBound(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	const flood = 300
	read := func() map[string]int {
		m := map[string]int{}
		for _, c := range []string{Blocked, Inbound, LogLines, EdgeDevice, CoreDevice, TrafficRefused(101), TrafficRefused(103)} {
			m[c] = h.counter(c)
		}
		return m
	}
	// At most a burst, and a minute's rate for each minute begun since.
	most := func(since time.Time) int { return LineBurst + LineRate*(int(time.Since(since)/time.Minute)+1) }
	moved := func(a, b map[string]int, c string) int { return b[c] - a[c] }

	// The TV (VLAN 101) floods an address on no list of its own.
	start, was := time.Now(), read()
	sendUDP(t, h.hosts["101"], "", netOther, 443, flood)
	time.Sleep(200 * time.Millisecond)
	now := read()
	if n := moved(was, now, Blocked); n != flood {
		t.Errorf("blocked moved %d for %d refused packets", n, flood)
	}
	if n := moved(was, now, TrafficRefused(101)); n != flood {
		t.Errorf("the TV's refusal count moved %d for %d refused packets", n, flood)
	}
	t.Logf("a flood of %d from a device wrote %d lines", flood, moved(was, now, LogLines))
	if n := moved(was, now, LogLines); n < 1 || n > most(start) {
		t.Errorf("a flood of %d wrote %d lines, want 1 to %d", flood, n, most(start))
	}

	// Another device's refusals log from their own bucket, all of them
	// while they fit in it.
	was = now
	sendUDP(t, h.hosts["103"], "", netOther, 443, LineBurst/2)
	time.Sleep(200 * time.Millisecond)
	now = read()
	if n := moved(was, now, LogLines); n != LineBurst/2 {
		t.Errorf("another device's %d refusals wrote %d lines", LineBurst/2, n)
	}
	if n := moved(was, now, TrafficRefused(103)); n != LineBurst/2 {
		t.Errorf("its refusal count moved %d", n)
	}
	if n := moved(was, now, TrafficRefused(101)); n != 0 {
		t.Errorf("its refusals were counted as the TV's (%d)", n)
	}

	// The internet floods the enforcer's own WAN address.
	start, was = time.Now(), now
	sendUDP(t, h.hosts["isp"], ispRouter, enfWAN, 9999, flood)
	time.Sleep(200 * time.Millisecond)
	now = read()
	if n := moved(was, now, Inbound); n != flood {
		t.Errorf("inbound moved %d for %d refused packets", n, flood)
	}
	if n := moved(was, now, LogLines); n < 1 || n > most(start) {
		t.Errorf("an inbound flood of %d wrote %d lines, want 1 to %d", flood, n, most(start))
	}

	// The edge opens connection after connection to the TV's control
	// port: each is accepted and counted, few are logged (#4762).
	const conns = 60
	start, was = time.Now(), now
	opened := 0
	within(t, h.hosts["edge"], func() {
		for range conns {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(devAddr(101), "80"), 2*time.Second)
			if err != nil {
				continue
			}
			opened++
			c.Close()
		}
	})
	time.Sleep(200 * time.Millisecond)
	now = read()
	if opened != conns {
		t.Errorf("%d of %d connections from the edge to the TV's control port opened", opened, conns)
	}
	if n := moved(was, now, EdgeDevice); n != conns {
		t.Errorf("edge_device moved %d for %d connections", n, conns)
	}
	if n := moved(was, now, LogLines); n < 1 || n > most(start) {
		t.Errorf("%d connections from the edge wrote %d lines, want 1 to %d", conns, n, most(start))
	}
	// The edge's connections to another device log from that device's
	// bucket, not the one its flood to the TV spent: the edge's lines are
	// bounded per device, so a rooted edge cannot hide its connections to
	// every device by flooding one (#4842, ENF-log-bound-1).
	was = now
	within(t, h.hosts["edge"], func() {
		for range LineBurst / 2 {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(devAddr(109), "80"), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
	})
	time.Sleep(200 * time.Millisecond)
	now = read()
	if n := moved(was, now, LogLines); n != LineBurst/2 {
		t.Errorf("the edge's %d connections to the hub after its flood to the TV wrote %d lines", LineBurst/2, n)
	}
	if n := moved(was, now, EdgeDevice); n != LineBurst/2 {
		t.Errorf("edge_device moved %d", n)
	}
	// The core's connections to another device log from their own bucket.
	was = now
	within(t, h.hosts["core"], func() {
		for range LineBurst / 2 {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(devAddr(102), "80"), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
	})
	time.Sleep(200 * time.Millisecond)
	now = read()
	if n := moved(was, now, LogLines); n != LineBurst/2 {
		t.Errorf("the core's %d connections wrote %d lines", LineBurst/2, n)
	}
	if n := moved(was, now, CoreDevice); n != LineBurst/2 {
		t.Errorf("core_device moved %d", n)
	}
}

// TestRefusedWhereExact (#4765, NET-5): a device that spends its bucket's
// lines on decoys first is still counted at its real destination, packet
// for packet, in its own refused set and in no other device's. Catches a
// summary a device can steer by choosing which refusals are logged.
func TestRefusedWhereExact(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	for i := range LineBurst {
		sendUDP(t, h.hosts["101"], "", "198.51.100."+strconv.Itoa(i+1), 443, 1)
	}
	const want = 25
	sendUDP(t, h.hosts["101"], "", netOther, 443, want)
	time.Sleep(200 * time.Millisecond)
	if n := h.refusedAt(RefusedSet(101, false), netOther); n != want {
		t.Errorf("the TV's refusals at %s count %d, want %d", netOther, n, want)
	}
	if n := h.refusedAt(RefusedSet(101, false), "198.51.100.1"); n != 1 {
		t.Errorf("a decoy counts %d, want 1", n)
	}
	if n := h.refusedAt(RefusedSet(103, false), netOther); n != 0 {
		t.Errorf("the TV's refusals counted for another device: %d", n)
	}
	if h.v6 {
		sendUDP(t, h.hosts["101"], "", net6Other, 443, 3)
		time.Sleep(200 * time.Millisecond)
		if n := h.refusedAt(RefusedSet(101, true), net6Other); n != 3 {
			t.Errorf("the TV's refusals at %s count %d, want 3", net6Other, n)
		}
	}
}

// sendUDP sends n datagrams from host from (from src, if given) to dst.
func sendUDP(t *testing.T, from *host, src, dst string, port, n int) {
	within(t, from, func() {
		var laddr *net.UDPAddr
		if src != "" {
			laddr = &net.UDPAddr{IP: net.ParseIP(src)}
		}
		c, err := net.DialUDP("udp", laddr, &net.UDPAddr{IP: net.ParseIP(dst), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for range n {
			if _, err := c.Write([]byte("refused")); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// refusedAt is the packets set counts for addr; 0 when addr is not in it.
func (h *home) refusedAt(set, addr string) int {
	out := run(h.t, "nft", "list", "set", "inet", Table, set)
	m := regexp.MustCompile(`(?:[{,]\s*)` + regexp.QuoteMeta(addr) + `\s[^,}]*?counter packets (\d+)`).FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}
