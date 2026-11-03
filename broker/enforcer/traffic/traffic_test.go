package traffic

// REQ: NET-5, NET-3

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

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
// prints: the TV reached n addresses over IPv4 and one over IPv6, and was
// refused 900 packets, at 11.0.0.200 twice, at 1.1.1.1 and at
// 2001:db8::bad once each (by packets, not bytes), and at refused more
// IPv4 addresses once each; another table's set and counter, and a set
// element with no counter, are noise.
func listing(n, refused int) []byte {
	var elems []string
	for i := 1; i <= n; i++ {
		elems = append(elems, fmt.Sprintf(`{"elem":{"val":"11.0.0.%d","expires":86000,"counter":{"packets":%d,"bytes":%d}}}`, i, i, 100*i))
	}
	ref := []string{`{"elem":{"val":"11.0.0.200","expires":86000,"counter":{"packets":2,"bytes":120}}}`, `{"elem":{"val":"1.1.1.1","expires":86000,"counter":{"packets":1,"bytes":9999}}}`}
	for i := range refused {
		ref = append(ref, fmt.Sprintf(`{"elem":{"val":"11.2.%d.%d","expires":86000,"counter":{"packets":1,"bytes":60}}}`, i/250, i%250))
	}
	return []byte(`{"nftables":[{"metainfo":{"version":"1.0.9","json_schema_version":1}},
{"table":{"family":"inet","name":"enforcer","handle":1}},
{"counter":{"family":"inet","name":"t101_out","table":"enforcer","handle":2,"packets":40,"bytes":5000}},
{"counter":{"family":"inet","name":"t101_in","table":"enforcer","handle":3,"packets":50,"bytes":90000}},
{"counter":{"family":"inet","name":"t101_refused","table":"enforcer","handle":10,"packets":900,"bytes":54000}},
{"counter":{"family":"inet","name":"guests_out","table":"enforcer","handle":4,"packets":7,"bytes":700}},
{"counter":{"family":"inet","name":"guests_in","table":"enforcer","handle":5,"packets":8,"bytes":800}},
{"counter":{"family":"inet","name":"guests_conns","table":"enforcer","handle":6,"packets":3,"bytes":180}},
{"counter":{"family":"inet","name":"t101_out","table":"other","handle":2,"packets":1,"bytes":999999}},
{"set":{"family":"inet","name":"t101_4","table":"enforcer","type":"ipv4_addr","handle":7,"size":64,"flags":["timeout","dynamic"],"timeout":86400,"elem":[` + strings.Join(elems, ",") + `]}},
{"set":{"family":"inet","name":"t101_6","table":"enforcer","type":"ipv6_addr","handle":8,"size":64,"flags":["timeout","dynamic"],"timeout":86400,"elem":[{"elem":{"val":"2001:db8::1","expires":86000,"counter":{"packets":1,"bytes":77}}},"2001:db8::2"]}},
{"set":{"family":"inet","name":"t101_refused_4","table":"enforcer","type":"ipv4_addr","handle":11,"size":1024,"flags":["timeout","dynamic"],"timeout":86400,"elem":[` + strings.Join(ref, ",") + `]}},
{"set":{"family":"inet","name":"t101_refused_6","table":"enforcer","type":"ipv6_addr","handle":12,"size":1024,"flags":["timeout","dynamic"],"timeout":86400,"elem":[{"elem":{"val":"2001:db8::bad","expires":86000,"counter":{"packets":1,"bytes":80}}}]}},
{"set":{"family":"inet","name":"t104_4","table":"other","type":"ipv4_addr","handle":9,"elem":[{"elem":{"val":"11.9.9.9","counter":{"packets":1,"bytes":5}}}]}}
]}`)
}

func reader(n, refused int) *Reader {
	return &Reader{Policy: doc, List: func() ([]byte, error) { return listing(n, refused), nil }}
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
	r := reader(11, 0)
	b, err := r.Read("tv")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := keys(t, b), []string{"addr", "blocked", "blocked_to", "bytes_in", "bytes_out", "count", "destinations", "device", "more_blocked", "more_destinations", "truncated"}; !slices.Equal(got, want) {
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
	if s.Truncated {
		t.Error("a device with room left is marked truncated")
	}
	if s.Blocked != 900 || !slices.Equal(s.BlockedTo, []Dest{{"11.0.0.200", 2}, {"1.1.1.1", 1}, {"2001:db8::bad", 1}}) || s.MoreBlocked != 0 {
		t.Errorf("blocked: %d %+v", s.Blocked, s.BlockedTo)
	}
	for _, perPacket := range []string{"40000", "443", "PROTO", "10.101.0.2", "port", "time"} {
		if strings.Contains(string(b), perPacket) {
			t.Errorf("the summary carries %q: %s", perPacket, b)
		}
	}

	// Short however busy the device: a summary is bounded by Top, not by
	// how many addresses the device reached or was refused.
	b, _ = reader(64, 500).Read("tv")
	if len(b) > 1024 {
		t.Errorf("a busy device's summary is %d bytes", len(b))
	}
	// Truncated marks a full counting set, or a full refusal set, alone.
	for name, c := range map[string]struct {
		dests, refused int
		want           bool
	}{"room": {nft.TrafficSize - 1, nft.RefusedSize - 3, false}, "set full": {nft.TrafficSize, 0, true}, "refused full": {3, nft.RefusedSize - 2, true}} {
		var got Summary
		if b, err := reader(c.dests, c.refused).Read("tv"); err != nil || json.Unmarshal(b, &got) != nil || got.Truncated != c.want {
			t.Errorf("%s: truncated %v, want %v (%v)", name, got.Truncated, c.want, err)
		}
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
		if err != nil || string(b) != `{"device":"`+id+`","bytes_out":0,"bytes_in":0,"destinations":[],"more_destinations":0,"blocked":0,"blocked_to":[],"more_blocked":0,"truncated":false}` {
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
