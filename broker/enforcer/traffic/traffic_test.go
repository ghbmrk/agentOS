package traffic

// REQ: NET-5, NET-3

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

func layout() nft.Layout { return nft.Layout{Trunk: "ap0", Guests: "gst0", Core: "core0"} }

func doc() policy.Document {
	return policy.Document{
		Version: 1,
		Devices: []policy.Device{
			{ID: "tv", Network: policy.NetDevices, WiFi: "vlan101", Allow: []string{"tv.example"}, VendorCloud: true, Everyday: true},
			{ID: "cam", Network: policy.NetDevices, WiFi: "vlan104", Class: policy.ClassCamera},
			{ID: "lock", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"},
			{ID: "visitor-phone", Network: policy.NetGuests, Everyday: true},
			{ID: "laptop", Network: policy.NetHousehold, Everyday: true},
		},
	}
}

// listing is nft's JSON for the enforcer table, in the shape nft 1.0.9
// prints: the TV reached n addresses over IPv4 and one over IPv6; another
// table's set and counter, and a set element with no counter, are noise.
func listing(n int) []byte {
	var elems []string
	for i := 1; i <= n; i++ {
		elems = append(elems, fmt.Sprintf(`{"elem":{"val":"11.0.0.%d","expires":86000,"counter":{"packets":%d,"bytes":%d}}}`, i, i, 100*i))
	}
	return []byte(`{"nftables":[{"metainfo":{"version":"1.0.9","json_schema_version":1}},
{"table":{"family":"inet","name":"enforcer","handle":1}},
{"counter":{"family":"inet","name":"t101_out","table":"enforcer","handle":2,"packets":40,"bytes":5000}},
{"counter":{"family":"inet","name":"t101_in","table":"enforcer","handle":3,"packets":50,"bytes":90000}},
{"counter":{"family":"inet","name":"guests_out","table":"enforcer","handle":4,"packets":7,"bytes":700}},
{"counter":{"family":"inet","name":"guests_in","table":"enforcer","handle":5,"packets":8,"bytes":800}},
{"counter":{"family":"inet","name":"guests_conns","table":"enforcer","handle":6,"packets":3,"bytes":180}},
{"counter":{"family":"inet","name":"t101_out","table":"other","handle":2,"packets":1,"bytes":999999}},
{"set":{"family":"inet","name":"t101_4","table":"enforcer","type":"ipv4_addr","handle":7,"size":64,"flags":["timeout","dynamic"],"timeout":86400,"elem":[` + strings.Join(elems, ",") + `]}},
{"set":{"family":"inet","name":"t101_6","table":"enforcer","type":"ipv6_addr","handle":8,"size":64,"flags":["timeout","dynamic"],"timeout":86400,"elem":[{"elem":{"val":"2001:db8::1","expires":86000,"counter":{"packets":1,"bytes":77}}},"2001:db8::2"]}},
{"set":{"family":"inet","name":"t104_4","table":"other","type":"ipv4_addr","handle":9,"elem":[{"elem":{"val":"11.9.9.9","counter":{"packets":1,"bytes":5}}}]}}
]}`)
}

func reader(n int) (*Reader, *Log) {
	log := NewLog("ap0")
	return &Reader{Policy: doc, Layout: layout(), List: func() ([]byte, error) { return listing(n), nil }, Log: log}, log
}

// keys is every JSON object key in b, at any depth.
func keys(t *testing.T, b []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				if !slices.Contains(out, k) {
					out = append(out, k)
				}
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(v)
	slices.Sort(out)
	return out
}

// NET-5: a Devices-network device's summary is per device: destination,
// bytes and blocked, short, and nothing per packet; Guests get nothing but
// the whole network's counters; Owner and Household are not inspected.
// Catches surveillance of guests.
func TestSummaryShape(t *testing.T) {
	r, log := reader(11)
	// Refusals: the TV's, a Guests line and an accepted core connection
	// (neither counts), and lines that only look like refusals.
	for i, l := range []string{
		"enf drop IN=ap0.101 OUT=wan0 MAC=aa:bb SRC=10.101.0.2 DST=11.0.0.200 LEN=60 PROTO=TCP SPT=40000 DPT=443",
		"enf drop IN=ap0.101 OUT=wan0 SRC=10.101.0.2 DST=11.0.0.200 LEN=60 PROTO=TCP SPT=40001 DPT=443",
		"enf dns IN=ap0.101 OUT=wan0 SRC=10.101.0.2 DST=1.1.1.1 LEN=60 PROTO=UDP SPT=5000 DPT=53",
		"enf drop IN=gst0 OUT=wan0 SRC=10.30.0.2 DST=11.0.0.9 LEN=60",
		"enf core-dev 101 IN=core0 OUT=ap0.101 SRC=10.50.0.2 DST=10.101.0.2 LEN=60",
		"kernel: enf drop IN=ap0.101 OUT=wan0 SRC=10.101.0.2 DST=11.0.0.66",
		"enf drop IN=ap0.1010 OUT=wan0 SRC=10.101.0.2 DST=11.0.0.66",
		"enf drop IN=ap0.101 OUT=wan0 SRC=10.101.0.2 DST=not-an-address",
		"enf drop IN=ap1.101 OUT=wan0 SRC=10.101.0.2 DST=11.0.0.66",
	} {
		log.Line(l, int64(1000+i))
	}

	b, err := r.Read("tv")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := keys(t, b), []string{"addr", "blocked", "blocked_to", "bytes_in", "bytes_out", "count", "destinations", "device", "more_blocked", "more_destinations"}; !slices.Equal(got, want) {
		t.Errorf("summary keys %q, want %q", got, want)
	}
	var s Summary
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Device != "tv" || s.BytesOut != 5000 || s.BytesIn != 90000 {
		t.Errorf("counters: %+v", s)
	}
	if len(s.Destinations) != Top || s.MoreDestinations != 12-Top || s.Destinations[0] != (Dest{"11.0.0.11", 1100}) || s.Destinations[Top-1] != (Dest{"11.0.0.4", 400}) {
		t.Errorf("destinations: %+v, %d more", s.Destinations, s.MoreDestinations)
	}
	if s.Blocked != 3 || !slices.Equal(s.BlockedTo, []Dest{{"11.0.0.200", 2}, {"1.1.1.1", 1}}) || s.MoreBlocked != 0 {
		t.Errorf("blocked: %d %+v", s.Blocked, s.BlockedTo)
	}
	for _, perPacket := range []string{"40000", "443", "PROTO", "10.101.0.2", "port", "time"} {
		if strings.Contains(string(b), perPacket) {
			t.Errorf("the summary carries %q: %s", perPacket, b)
		}
	}

	// Short however busy the device: a summary is bounded by Top, not by
	// how many addresses the device reached or was refused.
	busy, blog := reader(64)
	for i := range 500 {
		blog.Line(fmt.Sprintf("enf drop IN=ap0.101 OUT=wan0 SRC=10.101.0.2 DST=11.1.%d.%d LEN=60", i/250, i%250), 2000)
	}
	if b, _ := busy.Read("tv"); len(b) > 1024 {
		t.Errorf("a busy device's summary is %d bytes", len(b))
	}
	if n, by := blog.of(101); n != 500 || len(by) != nft.TrafficSize {
		t.Errorf("the refusal log keeps %d addresses for %d refusals", len(by), n)
	}

	// Guests: only the whole network's counters, whichever guest asks.
	b, err = r.Read("visitor-phone")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := keys(t, b), []string{"bytes_in", "bytes_out", "connections", "network"}; !slices.Equal(got, want) {
		t.Errorf("guests keys %q, want %q", got, want)
	}
	if string(b) != `{"network":"guests","bytes_out":700,"bytes_in":800,"connections":3}` {
		t.Errorf("guests: %s", b)
	}
	if strings.Contains(string(b), "visitor-phone") || strings.Contains(string(b), "11.0.0.9") {
		t.Errorf("a guest is named or followed: %s", b)
	}

	// A camera with no traffic, and a radio lock with no IP path: zero.
	for _, id := range []string{"cam", "lock"} {
		b, err := r.Read(id)
		if err != nil || string(b) != `{"device":"`+id+`","bytes_out":0,"bytes_in":0,"destinations":[],"more_destinations":0,"blocked":0,"blocked_to":[],"more_blocked":0}` {
			t.Errorf("%s: %s %v", id, b, err)
		}
	}
	if _, err := r.Read("laptop"); !errors.Is(err, ErrNotInspected) {
		t.Errorf("household: %v", err)
	}
	if _, err := r.Read("stranger"); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown device: %v", err)
	}
	r.List = func() ([]byte, error) { return []byte("{"), nil }
	if _, err := r.Read("tv"); !errors.Is(err, ErrListing) {
		t.Errorf("a broken listing: %v", err)
	}
}

// The refusal log keeps one Window: a day after it started, it starts
// again, so blocked counts are a day's, not forever's.
func TestRefusalWindow(t *testing.T) {
	log := NewLog("ap0")
	line := "enf drop IN=ap0.101 OUT=wan0 SRC=10.101.0.2 DST=::ffff:11.0.0.1 LEN=60"
	log.Line(line, 0)
	log.Line(line, Window-1)
	if n, by := log.of(101); n != 2 || by[netip.MustParseAddr("11.0.0.1")] != 2 {
		t.Fatalf("within the window: %d %v", n, by)
	}
	log.Line(line, Window)
	if n, _ := log.of(101); n != 1 {
		t.Errorf("after the window: %d", n)
	}
	log.Line(line, 5) // the clock went back
	if n, _ := log.of(101); n != 1 {
		t.Errorf("after the clock went back: %d", n)
	}
}

// Every prefix the summaries count is a refusal in the compiled ruleset,
// and every rule there that logs and drops uses one of them, so a device's
// blocked count is exactly what the firewall refused it.
func TestPrefixesAreRefusals(t *testing.T) {
	text, err := nft.Compile(doc(), nft.Layout{
		WAN: "wan0", Owner: "own0", Household: "hh0", Guests: "gst0", Admin: "adm0",
		Core: "core0", Edge: "edge0", Trunk: "ap0", APMgmt: "apm0",
		APAdmin: []netip.Addr{netip.MustParseAddr("10.70.0.2")}, ISP: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		EdgeGateway: netip.MustParseAddr("10.60.0.1"), PagePort: 8443, ChannelPort: 7443, CorePagePort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		_, after, ok := strings.Cut(l, `log prefix "`)
		if !ok {
			continue
		}
		prefix, _, _ := strings.Cut(after, `"`)
		blocked := slices.Contains(nft.BlockedPrefixes, prefix)
		if drops := strings.HasSuffix(l, " drop"); drops != blocked {
			t.Errorf("prefix %q counted %v, rule drops %v: %s", prefix, blocked, drops, strings.TrimSpace(l))
		}
		seen[prefix] = true
	}
	for _, p := range nft.BlockedPrefixes {
		if !seen[p] {
			t.Errorf("prefix %q is in no rule", p)
		}
	}
}
