package nft

// REQ: NET-5, NET-3

import (
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRefusalLinesBound (#4432, P4): every refusal goes to its prefix's
// refuse chain, which counts it on the prefix's counter and on its
// device's, logs it only within its interface's bucket, and drops it; no
// other rule logs a refusal, so no rule writes a line per refused packet.
// Catches a refusal logged without a bound, a bound that skips the count
// or the drop, and a device whose refusals are not counted.
func TestRefusalLinesBound(t *testing.T) {
	text, err := Compile(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	text = withDrops(t, fixturePolicy(), text) // a cap's refusals are in the drop state
	cs := chains(text)
	limit := " { iif limit rate " + strconv.Itoa(LineRate) + "/minute burst " + strconv.Itoa(LineBurst) + " packets }"
	for _, r := range refusals {
		want := []string{
			`counter name "` + r.counter + `"`,
			"counter name iifname map @refused",
			"update @" + lines(r.prefix) + limit + ` counter name "` + LogLines + `" log prefix "` + r.prefix + `" drop`,
			"drop",
		}
		if got := cs[refuse(r.prefix)]; !slices.Equal(got, want) {
			t.Errorf("chain %s:\n%q\nwant\n%q", refuse(r.prefix), got, want)
		}
		decl := "set " + lines(r.prefix) + " {\n\t\ttypeof iif;\n\t\tsize " + strconv.Itoa(LineSize) + ";\n\t\tflags dynamic,timeout;\n\t\ttimeout " + secs(LineIdle) + ";\n\t}"
		if !strings.Contains(text, decl) {
			t.Errorf("no %q", decl)
		}
	}
	// Every refuse chain's line carries a prefix the traffic reader
	// counts as a refusal (BlockedPrefixes), and each prefix has a chain.
	var logged []string
	for name, rs := range cs {
		if !strings.HasPrefix(name, "refuse_") {
			continue
		}
		for _, r := range rs {
			if _, p, ok := strings.Cut(r, `log prefix "`); ok {
				p, _, _ = strings.Cut(p, `"`)
				logged = append(logged, p)
				if !slices.Contains(BlockedPrefixes, p) {
					t.Errorf("chain %s logs %q, which BlockedPrefixes does not name", name, p)
				}
			}
		}
	}
	if slices.Sort(logged); !slices.Equal(logged, slices.Sorted(slices.Values(BlockedPrefixes))) {
		t.Errorf("refuse chains log %q, BlockedPrefixes is %q", logged, BlockedPrefixes)
	}
	for name, rs := range cs {
		if strings.HasPrefix(name, "refuse_") {
			continue
		}
		for _, r := range rs {
			for _, p := range BlockedPrefixes {
				if strings.Contains(r, `log prefix "`+p+`"`) {
					t.Errorf("chain %s logs a refusal outside its refuse chain: %s", name, r)
				}
			}
		}
	}
	// Each refusal prefix is reached, from its rules' first form only.
	for _, p := range BlockedPrefixes {
		if !strings.Contains(text, "goto "+refuse(p)) {
			t.Errorf("nothing goes to %s", refuse(p))
		}
	}
	for _, r := range append(cs[live("forward")], cs[live("people")]...) {
		if strings.Contains(r, "goto refuse_") && !strings.HasPrefix(r, "ct state related ") {
			t.Errorf("a live rule refuses with a line: %s", r)
		}
	}
	// Every device, isolated or not, has its refusal counter.
	var elems []string
	for _, v := range []int{101, 102, 103, 104, 105, 106, 107, 108} {
		elems = append(elems, strconv.Quote(fixtureLayout().deviceIface(v))+" : "+strconv.Quote(TrafficRefused(v)))
		if !strings.Contains(text, "counter "+TrafficRefused(v)+" { }") {
			t.Errorf("no counter %s", TrafficRefused(v))
		}
	}
	if !strings.Contains(text, "map refused {\n\t\ttype ifname : counter;\n\t\telements = { "+strings.Join(elems, ", ")+" }\n\t}") {
		t.Error("the refused map does not name every device's counter")
	}
	none := fixturePolicy()
	none.Devices, none.Pairs = nil, nil
	text, err = Compile(none, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "map refused {\n\t\ttype ifname : counter;\n\t}") {
		t.Error("with no devices the refused map is not empty")
	}
}

// TestRefusalFloodBound (#4432, NET-5, P4): a device flooding refused
// packets, and the internet flooding the enforcer's WAN, write at most
// their buckets' lines, while the refusal counters and the device's own
// count move by every packet; another device's refusals still log, from a
// bucket of their own. The kernel log is unreadable from a test namespace,
// so the lines are read from log_lines, the counter of the rule that
// writes them. Catches a refusal line per packet (a device fills the
// journal) and a bound that loses counts.
func TestRefusalFloodBound(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	const flood = 300
	send := func(from *host, src, dst string, port, n int) {
		within(t, from, func() {
			var laddr *net.UDPAddr
			if src != "" {
				laddr = &net.UDPAddr{IP: net.ParseIP(src)}
			}
			c, err := net.DialUDP("udp4", laddr, &net.UDPAddr{IP: net.ParseIP(dst), Port: port})
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
	read := func() map[string]int {
		m := map[string]int{}
		for _, c := range []string{Blocked, Inbound, LogLines, TrafficRefused(101), TrafficRefused(103)} {
			m[c] = h.counter(c)
		}
		return m
	}
	// At most a burst, and a minute's rate for each minute begun since.
	most := func(since time.Time) int { return LineBurst + LineRate*(int(time.Since(since)/time.Minute)+1) }
	moved := func(a, b map[string]int, c string) int { return b[c] - a[c] }

	// The TV (VLAN 101) floods an address on no list of its own.
	start, was := time.Now(), read()
	send(h.hosts["101"], "", netOther, 443, flood)
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
	send(h.hosts["103"], "", netOther, 443, LineBurst/2)
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
	send(h.hosts["isp"], ispRouter, enfWAN, 9999, flood)
	time.Sleep(200 * time.Millisecond)
	now = read()
	if n := moved(was, now, Inbound); n != flood {
		t.Errorf("inbound moved %d for %d refused packets", n, flood)
	}
	if n := moved(was, now, LogLines); n < 1 || n > most(start) {
		t.Errorf("an inbound flood of %d wrote %d lines, want 1 to %d", flood, n, most(start))
	}
}
