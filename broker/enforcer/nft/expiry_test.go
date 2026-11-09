package nft

// REQ: NET-2, NET-3

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// refresh runs the resolver's step the way the enforcer does: the running
// table's listing through Refresh, then the loader's Update.
func (h *home) refresh(d policy.Document) {
	h.t.Helper()
	l := loader(h.t)
	running, err := l.List(context.Background(), Table)
	if err != nil {
		h.t.Fatal(err)
	}
	text, err := Refresh(d, fixtureLayout(), running)
	if err != nil {
		h.t.Fatal(err)
	}
	if text == "" {
		return
	}
	if err := l.Update(context.Background(), text); err != nil {
		h.t.Fatal(err)
	}
}

// expiries is each element of the running table's set with the seconds it
// has left; 0 for an element with no expiry.
func (h *home) expiries(set string) map[string]int64 {
	h.t.Helper()
	var doc struct {
		Nftables []struct {
			Set *listedSet `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(run(h.t, "nft", "-j", "list", "set", "inet", Table, set)), &doc); err != nil {
		h.t.Fatal(err)
	}
	out := map[string]int64{}
	for _, o := range doc.Nftables {
		if o.Set == nil {
			continue
		}
		for _, raw := range o.Set.Elem {
			var a string
			if json.Unmarshal(raw, &a) == nil {
				out[a] = 0
				continue
			}
			var e struct {
				Elem struct {
					Val     string `json:"val"`
					Expires int64  `json:"expires"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				h.t.Fatal(err)
			}
			out[e.Elem.Val] = e.Elem.Expires
		}
	}
	return out
}

// age leaves addr in the fresh or recent set set with only n seconds left, as
// if its answer's AnswerTimeout had nearly run (n seconds left): the clock the test cannot
// wait out.
func (h *home) age(set, addr string, n int) {
	h.t.Helper()
	run(h.t, "nft", "delete element inet "+Table+" "+set+" { "+addr+" }; add element inet "+Table+" "+set+" { "+addr+" expires "+secs(n)+" }")
}

// NET-2 The core's list ("only the addresses … that answer returns"),
// NET-3 (#4453): an answer takes new connections from the moment the
// resolver adds it until AnswerTimeout after the next refresh. An address
// no answer has returned for longer than that takes no new connection,
// while a connection open to it that stays busy goes on; a device that
// resolves again keeps its address, even when its last refresh is about to
// run out before the next one. Catches allow sets that keep every address
// a listed name ever answered open to new connections (ENF-f-3's old
// class), and an expiry that cuts a busy connection or a device that keeps
// resolving.
func TestAnswersExpire(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d := cutPolicy()
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, d, text))
	tv, _ := allowSetOf(t, d, DeviceSet(101, false))
	recent, fresh := tv.Recent(false), tv.Fresh(false)
	dial := func(want outcome, why string) {
		t.Helper()
		h.expect(probe{from: "101", addr: netAllow, port: 80, want: want, why: why})
	}

	expired := h.counter(Expired)
	dial(silent, "a device dials an address before any answer")
	if n := h.counter(Expired) - expired; n != 0 {
		t.Errorf("a dial to an address no answer returned moved the expired counter by %d", n)
	}
	h.answer(d, DeviceSet(101, false), "tv.example", netAllow)
	if left, ok := h.expiries(fresh)[netAllow]; !ok || left < AnswerTimeout-5 || left > AnswerTimeout {
		t.Errorf("a fresh answer has %ds left (held %v), want about %d", left, ok, AnswerTimeout)
	}
	dial(connected, "a device dials its answer before any refresh")
	busy := h.hold("a connection that stays busy", "101", "isp", netAllow, 9251)

	h.refresh(d)
	if got := h.expiries(fresh); len(got) != 0 {
		t.Errorf("the fresh set holds %v after a refresh", got)
	}
	if left, ok := h.expiries(recent)[netAllow]; !ok || left < AnswerTimeout-5 || left > AnswerTimeout {
		t.Fatalf("after a refresh the answer has %ds left (held %v), want about %d", left, ok, AnswerTimeout)
	}
	dial(connected, "a device dials its answer after a refresh")

	// The answer runs out with no new one: no new connection, and the
	// busy one goes on.
	h.age(recent, netAllow, 1)
	time.Sleep(1500 * time.Millisecond)
	if _, ok := h.expiries(recent)[netAllow]; ok {
		t.Fatal("an answer past its time is still in the recent set")
	}
	expired = h.counter(Expired)
	dial(silent, "a device dials an address no answer returned for longer than AnswerTimeout")
	if h.counter(Expired) == expired {
		t.Error("a dial to an expired answer was not refused with its reason (the expired counter, LogExpired)")
	}
	h.expectOpen(true, busy)

	// The device resolves again while its last refresh is about to run
	// out: the new answer holds the address after the old one expires and
	// before the next refresh, and the refresh gives it a full timeout.
	h.answer(d, DeviceSet(101, false), "tv.example", netAllow)
	h.refresh(d)
	h.age(recent, netAllow, 1)
	h.answer(d, DeviceSet(101, false), "tv.example", netAllow)
	time.Sleep(1500 * time.Millisecond)
	dial(connected, "a device that resolved again, after its last refresh ran out")
	h.refresh(d)
	if left := h.expiries(recent)[netAllow]; left < AnswerTimeout-5 {
		t.Errorf("a new answer refreshed to %ds, want about %d", left, AnswerTimeout)
	}
	dial(connected, "a device that resolved again, after the next refresh")
	h.expectOpen(true, busy)

	// A load carries the fresh and recent answers of a kept name, the
	// recent one with the time it had left.
	h.answer(d, DeviceSet(101, false), "tv.example", netAllow)
	h.age(recent, netAllow, 300)
	h.reload(d)
	if left := h.expiries(recent)[netAllow]; left < 290 || left > 300 {
		t.Errorf("a load carried the recent answer with %ds left, want about 300", left)
	}
	if left, ok := h.expiries(fresh)[netAllow]; !ok || left > AnswerTimeout {
		t.Errorf("a load carried a fresh answer of a kept name with %ds left (held %v)", left, ok)
	}
	h.expectOpen(true, busy)

	// #5116: no refresh runs (the step keeps failing). A fresh answer
	// takes new connections for AnswerTimeout from its first add, which
	// answering again does not restart, and then none.
	h.age(recent, netAllow, 1)
	h.age(fresh, netAllow, 2)
	h.answer(d, DeviceSet(101, false), "tv.example", netAllow)
	if left := h.expiries(fresh)[netAllow]; left > 2 {
		t.Errorf("answering again restarted a fresh answer's time: %ds left", left)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, ok := h.expiries(fresh)[netAllow]; ok {
		t.Fatal("a fresh answer past AnswerTimeout is still in the fresh set")
	}
	expired = h.counter(Expired)
	dial(silent, "a device dials a fresh answer no refresh moved for AnswerTimeout")
	if h.counter(Expired) == expired {
		t.Error("a dial to a fresh answer past its time was not refused as expired")
	}
	h.expectOpen(true, busy)
}

// NET-2 The core's list (#4453): Refresh moves each fresh set's addresses
// of its own family, each once, into the recent set with a full timeout
// (deleted and added again, since adding an element a set holds keeps
// its expiry) and out of the fresh set, in a text the loader's Update
// takes. Nothing else changes: no recent element without a fresh answer,
// no set of another family or table, no element in any other form.
func TestRefreshMovesFreshAnswers(t *testing.T) {
	l := fixtureLayout()
	d := twoNames()
	tv, _ := allowSetOf(t, d, DeviceSet(101, false))
	core, _ := allowSetOf(t, d, CoreSet(false))
	aged := func(addr string) raw { return raw{`{"elem": {"val": "` + addr + `", "expires": 30}}`} }
	running := listing(map[string][]any{
		// A fresh answer is listed with the time its own timeout has left
		// (#5116); a plain one, as a fresh set without a timeout held it,
		// one with no time left, more than AnswerTimeout, or a timeout of
		// its own, is not one.
		tv.Fresh(false): {aged("203.0.113.20"), aged("203.0.113.10"), aged("203.0.113.10"), aged("2001:db8::1"), aged("fe80::1%eth0"), aged("::ffff:203.0.113.60"),
			raw{`{"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}, "expires": 30}}`}, "203.0.113.70",
			raw{`{"elem": {"val": "203.0.113.71", "expires": 0}}`}, raw{`{"elem": {"val": "203.0.113.72", "expires": 601}}`},
			raw{`{"elem": {"val": "203.0.113.73", "timeout": 60, "expires": 30}}`}},
		tv.Fresh(true):                     {aged("2001:db8::10")},
		tv.Recent(false):                   {raw{`{"elem": {"val": "203.0.113.30", "expires": 20}}`}},
		core.Recent(false):                 {raw{`{"elem": {"val": "203.0.113.40", "expires": 20}}`}},
		"ip/enforcer/" + core.Fresh(false): {aged("203.0.113.91")},
		"inet/other/" + core.Fresh(false):  {aged("203.0.113.92")},
	})
	got, err := Refresh(d, l, running)
	if err != nil {
		t.Fatal(err)
	}
	el4, el6 := " { 203.0.113.10, 203.0.113.20 }", " { 2001:db8::10 }"
	r4, f4, r6, f6 := "inet enforcer "+tv.Recent(false), "inet enforcer "+tv.Fresh(false), "inet enforcer "+tv.Recent(true), "inet enforcer "+tv.Fresh(true)
	want := strings.Join([]string{
		"add element " + r4 + el4, "delete element " + r4 + el4, "add element " + r4 + el4,
		"add element " + f4 + el4, "delete element " + f4 + el4,
		"add element " + r6 + el6, "delete element " + r6 + el6, "add element " + r6 + el6,
		"add element " + f6 + el6, "delete element " + f6 + el6,
	}, "\n") + "\n"
	if got != want {
		t.Errorf("refresh:\n%s\nwant:\n%s", got, want)
	}
	if err := (load.Loader{Bin: "/nonexistent/nft"}).Update(context.Background(), got); err == nil || strings.Contains(err.Error(), "not a byte-cap drop update") {
		t.Errorf("Update refused the refresh for its form: %v", err)
	}

	if got, err := Refresh(d, l, listing(map[string][]any{tv.Recent(false): {raw{`{"elem": {"val": "203.0.113.30", "expires": 20}}`}}})); err != nil || got != "" {
		t.Errorf("no fresh answer: %v, %q", err, got)
	}
	if _, err := Refresh(d, l, []byte("table inet enforcer {")); err == nil {
		t.Error("a listing that is not JSON was refreshed")
	}
	if _, err := Refresh(policy.Document{Devices: []policy.Device{{ID: "x", WiFi: "bad"}}}, l, running); err == nil {
		t.Error("a document Compile refuses was refreshed")
	}
}

// The loader's Update takes an element-only text (Refresh) in the fresh
// and recent sets only, and nothing that could change a rule, a set or a
// chain, another set's elements (#5116: a delete from a deny set would
// open it), or carry a second statement on an element line.
func TestUpdateTakesOnlyElementChanges(t *testing.T) {
	l := load.Loader{Bin: "/nonexistent/nft"}
	for _, text := range []string{
		"",
		"\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 }",
		"add element inet enforcer d101_4_r { 203.0.113.10 }\n\n",
		"add element inet other d101_4_r { 203.0.113.10 }\n",
		"add element ip enforcer d101_4_r { 203.0.113.10 }\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 }; flush ruleset\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 } ; add rule inet enforcer forward accept { 1.1.1.1 }\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 timeout 1d }\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 }\nadd rule inet enforcer forward accept\n",
		"flush set inet enforcer d101_4_r { 203.0.113.10 }\n",
		"add element inet enforcer D101 { 203.0.113.10 }\n",
		"add element inet enforcer { 203.0.113.10 }\n",
		"add element inet enforcer d101_4_r {  }\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 }\r\n",
		// Only the fresh and recent sets (#5116): not a deny set, an allow
		// set, a name's set, a byte cap's or a shared segment's.
		"delete element inet enforcer doh_4 { 1.1.1.1 }\n",
		"delete element inet enforcer nonglobal_4 { 10.0.0.0 }\n",
		"add element inet enforcer d101_4 { 203.0.113.10 }\n",
		"add element inet enforcer core_6 { 2001:db8::1 }\n",
		"add element inet enforcer " + named(DeviceSet(101, false), "tv", "tv.example") + " { 203.0.113.10 }\n",
		"add element inet enforcer capd_4 { 203.0.113.10 }\n",
		"add element inet enforcer ap_4 { 192.0.2.1 }\n",
		"add element inet enforcer d101_4_r { 203.0.113.10 }\ndelete element inet enforcer doh_4 { 1.1.1.1 }\n",
		"add element inet enforcer d101_4_x { 203.0.113.10 }\n",
		"add element inet enforcer d0101_4_r { 203.0.113.10 }\n",
		"add element inet enforcer xd101_4_r { 203.0.113.10 }\n",
		"add element inet enforcer core_4_fr { 203.0.113.10 }\n",
	} {
		if err := l.Update(context.Background(), text); err == nil || !strings.Contains(err.Error(), "not a byte-cap drop update or an answer refresh") {
			t.Errorf("Update(%q): %v, want refused for its form", text, err)
		}
	}
	ok := []string{
		"add element inet " + Table + " d101_4_r { 203.0.113.10, 2001:db8::1 }\n",
		"delete element inet " + Table + " core_6_f { 2001:db8::1 }\nadd element inet " + Table + " core_6_r { ::1 }\n",
	}
	// Every fresh and recent set the ruleset declares, which keeps the
	// loader's pattern equal to AllowSet's names.
	sets, err := AllowSets(fixturePolicy(), fixtureLayout())
	if err != nil || len(sets) < 2 {
		t.Fatalf("fixture allow sets: %v, %v", sets, err)
	}
	for _, a := range sets {
		for _, v6 := range []bool{false, true} {
			for _, s := range []string{a.Fresh(v6), a.Recent(v6)} {
				ok = append(ok, "add element inet "+Table+" "+s+" { 203.0.113.10 }\n")
			}
		}
	}
	for _, text := range ok {
		if err := l.Update(context.Background(), text); err == nil || strings.Contains(err.Error(), "not a byte-cap drop update") {
			t.Errorf("Update(%q) refused for its form: %v", text, err)
		}
	}
}

// NET-2 The core's list (#4453, #5116): a load carries a kept name's
// fresh and recent answers, each with the time it has left, and nothing
// else: not an address only a dropped name answered, not an element with
// more than AnswerTimeout or no time left, or with a timeout of its own,
// or with no expiry (a fresh set from before it had a timeout), not one
// of the wrong family.
func TestReloadCarriesFreshAndRecent(t *testing.T) {
	l := fixtureLayout()
	wide, narrow := twoNames(), cutPolicy()
	tv, _ := allowSetOf(t, wide, DeviceSet(101, false))
	elem := func(addr, rest string) raw { return raw{`{"elem": {"val": "` + addr + `"` + rest + `}}`} }
	running := listing(map[string][]any{
		tv.Named("tv.example", false):  {"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"},
		tv.Named("cdn.example", false): {"203.0.113.20"},
		tv.Named("tv.example", true):   {"2001:db8::10", "::1.2.3.4"},
		tv.Fresh(false):                {elem("203.0.113.10", `, "expires": 500`), elem("203.0.113.20", `, "expires": 500`), elem("203.0.113.99", `, "expires": 500`), elem("2001:db8::10", `, "expires": 500`), "203.0.113.11", elem("203.0.113.14", `, "expires": 0`)},
		tv.Recent(false): {
			elem("203.0.113.14", `, "expires": 90`),
			elem("203.0.113.11", `, "expires": 120`),
			raw{`{"elem": {"val": {"prefix": {"addr": "203.0.113.10", "len": 32}}, "expires": 60}}`},
			elem("203.0.113.010", `, "expires": 60`),
			elem("203.0.113.12", `, "expires": 601`),
			elem("203.0.113.13", `, "expires": 0`),
			elem("203.0.113.13", `, "timeout": 60, "expires": 30`),
			elem("203.0.113.20", `, "expires": 120`),
			elem("2001:db8::10", `, "expires": 120`),
		},
		tv.Recent(true): {elem("2001:db8::10", `, "expires": 600`), elem("::1.2.3.4", `, "expires": 100`)},
	})
	got, err := Reload(narrow, l, running)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"add element inet enforcer " + tv.Fresh(false) + " { 203.0.113.10 expires 500s }\n",
		"add element inet enforcer " + tv.Recent(false) + " { 203.0.113.11 expires 120s, 203.0.113.14 expires 90s }\n",
		// nft prints an IPv4-compatible address as ::1.2.3.4, Go as ::102:304.
		"add element inet enforcer " + tv.Recent(true) + " { 2001:db8::10 expires 600s, ::102:304 expires 100s }\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("reload lacks %q", want)
		}
	}
	for _, bad := range []string{"203.0.113.20", "203.0.113.99", "203.0.113.12 expires", "203.0.113.13 expires", "203.0.113.10 expires 60s", "203.0.113.010"} {
		if strings.Contains(got, bad) {
			t.Errorf("reload carried %s", bad)
		}
	}
	if strings.Contains(got, "add element inet enforcer "+tv.Fresh(true)) {
		t.Error("an IPv6 address listed in the IPv4 fresh set was carried")
	}
}
