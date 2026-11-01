package policy

// REQ: NET-3

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

func mdnsOf(s ...string) [][]string {
	var out [][]string
	for _, n := range s {
		out = append(out, strings.Split(n, "."))
	}
	return out
}

// TestMDNSNames: a device pins mDNS host and service instance names
// (#4144). A name of any other shape, or with a label a person cannot
// read as it is, is refused, so the relay never gets a pin it could not
// match and the signed screen never shows one that reads as another.
func TestMDNSNames(t *testing.T) {
	ok := []string{"printer.local", "Office Printer._ipp._tcp.local", "Café._smb._tcp.local", "tv._airplay._tcp.LOCAL", "x._hap._udp.local", strings.Repeat("a", 63) + ".local"}
	bad := [][]string{
		{"printer"}, {"local"}, {"printer", "example"}, {"_printer", "local"}, {"a", "b", "local"},
		{"x", "ipp", "_tcp", "local"}, {"x", "_", "_tcp", "local"}, {"x", "_ipp", "_sctp", "local"}, {"_ipp", "_tcp", "local"},
		{"x", "y", "_ipp", "_tcp", "local"}, {"", "local"}, {" ", "local"}, {"a.b", "local"},
		{strings.Repeat("a", 64), "local"}, {"‮abc", "local"}, {"a​b", "local"}, {"a\x00", "local"},
		{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 57) + "x", "local"},
		{strings.Repeat("a", 63), "_" + strings.Repeat("b", 62), "_tcp", strings.Repeat("c", 63)},
	}
	for _, n := range ok {
		if _, err := Encode(edit(1, func(d *Document) { dev(d, "tv").MDNS = mdnsOf(n) })); err != nil {
			t.Errorf("%q refused: %v", n, err)
		}
	}
	for _, n := range bad {
		if _, err := Encode(edit(1, func(d *Document) { dev(d, "tv").MDNS = [][]string{n} })); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v, want ErrMalformed", n, err)
		}
	}
	hostiletext.Run(t, mdnsLabel)
}

// TestMDNSCanonical: a device's names are sorted by mDNS name and
// deduplicated; a device with none writes no field, so documents from
// before #4144 keep their encoding and hash, and an empty list is not a
// second encoding of none.
func TestMDNSCanonical(t *testing.T) {
	plain, err := Encode(home(1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "mdns") {
		t.Errorf("a document with no pins writes the field: %s", plain)
	}
	a, err := Encode(edit(1, func(d *Document) {
		dev(d, "tv").MDNS = mdnsOf("tv.local", "Living Room._airplay._tcp.local", "tv.local")
	}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(edit(1, func(d *Document) { dev(d, "tv").MDNS = mdnsOf("Living Room._airplay._tcp.local", "tv.local") }))
	if err != nil || string(a) != string(b) {
		t.Errorf("order or repeats change the encoding:\n%s\n%s", a, b)
	}
	if _, err := Decode(a); err != nil {
		t.Errorf("a canonical document with pins: %v", err)
	}
	empty := strings.Replace(string(plain), `"label":"","control":[{"proto":"tcp","num":8008}],"stream":[]`, `"label":"","control":[{"proto":"tcp","num":8008}],"stream":[],"mdns":[]`, 1)
	if empty == string(plain) {
		t.Fatal("the test did not find the tv")
	}
	if _, err := Decode([]byte(empty)); !errors.Is(err, ErrMalformed) {
		t.Errorf("an empty list decoded: %v", err)
	}
}

// TestMDNSNameHeldOnce: no two devices pin one name, as mDNS compares
// names (ASCII case folded), whatever their networks: a Household
// device's name is held for it, so no paired device may pin it, and two
// devices on different links never both lose a name the owner did not
// see collide (#4144, UX lens on #4145). The refusal names the name and
// both devices, so the owner can rename one before signing; a device
// repeating one name in two cases is refused the same way.
func TestMDNSNameHeldOnce(t *testing.T) {
	for _, c := range []struct {
		what  string
		edit  func(d *Document)
		words []string
	}{
		{"two paired devices", func(d *Document) {
			dev(d, "tv").MDNS = mdnsOf("Living Room._airplay._tcp.local")
			dev(d, "speaker").MDNS = mdnsOf("living room._AirPlay._tcp.local")
		}, []string{`"Living Room._airplay._tcp.local"`, "speaker's and tv's"}},
		{"a Household name", func(d *Document) {
			d.Devices = append(d.Devices, Device{ID: "laptop", Network: NetHousehold, Everyday: true, MDNS: mdnsOf("laptop.local")})
			dev(d, "speaker").MDNS = mdnsOf("Laptop.local")
		}, []string{`"Laptop.local"`, "laptop's and speaker's"}},
		{"one device, two cases", func(d *Document) { dev(d, "tv").MDNS = mdnsOf("tv.local", "TV.local") }, []string{"tv's and tv's"}},
		{"A and a", func(d *Document) { dev(d, "tv").MDNS = mdnsOf("A.local"); dev(d, "speaker").MDNS = mdnsOf("a.local") }, []string{"speaker's and tv's"}},
		{"Z and z", func(d *Document) { dev(d, "tv").MDNS = mdnsOf("Z.local"); dev(d, "speaker").MDNS = mdnsOf("z.local") }, []string{"speaker's and tv's"}},
	} {
		_, err := Encode(edit(1, c.edit))
		if !errors.Is(err, ErrNameHeld) {
			t.Errorf("%s: %v, want ErrNameHeld", c.what, err)
			continue
		}
		for _, w := range c.words {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q does not name %s", c.what, err, w)
			}
		}
	}
	// Renamed, it is signed.
	if _, err := Encode(edit(1, func(d *Document) {
		dev(d, "tv").MDNS = mdnsOf("Living Room._airplay._tcp.local")
		dev(d, "speaker").MDNS = mdnsOf("Kitchen._airplay._tcp.local")
	})); err != nil {
		t.Errorf("renamed: %v", err)
	}
}
