package attest

// REQ: OSS-4, OSS-8

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// dmi is a fake /sys/class/dmi/id holding the named files.
func dmi(vendor, model, firmware string) fstest.MapFS {
	fs := fstest.MapFS{}
	for name, v := range map[string]string{DMIVendor: vendor, DMIModel: model, DMIFirmware: firmware} {
		if v != "-" {
			fs[name] = &fstest.MapFile{Data: []byte(v + "\n")}
		}
	}
	return fs
}

func measureSchema(t *testing.T) *Schema {
	t.Helper()
	s, err := Parse([]byte(doc(map[string]string{
		"hardware": `{"geekom": {"air12_lite": ["1.05", "2.0"]}, "acme": {"box_1": []}}`,
		"versions": `{"openclaw": ["2026.9.8"], "node": ["24.21.0"], "chromium": ["140.0.7339.80"]}`,
	})))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestOSS4MeasureFillsHardwareFromDMI (attest A9, security C2 on #73): the
// attesting package fills hardware from measured DMI data, normalised to
// the schema's token form, and uses Unlisted exactly when the measured
// value is not listed: an unlisted level makes every level below it
// Unlisted, and a missing, empty or placeholder value is not listed.
func TestOSS4MeasureFillsHardwareFromDMI(t *testing.T) {
	s := measureSchema(t)
	for _, c := range []struct {
		vendor, model, firmware string
		want                    Hardware
	}{
		{"GEEKOM", "Air12 Lite", "1.05", Hardware{"geekom", "air12_lite", "1.05"}},
		{"  GEEKOM ", "AIR12   LITE", " 2.0 ", Hardware{"geekom", "air12_lite", "2.0"}},
		{"GEEKOM", "Air12 Lite", "1.06", Hardware{"geekom", "air12_lite", Unlisted}},
		{"GEEKOM", "Air12 Lite", "-", Hardware{"geekom", "air12_lite", Unlisted}},
		{"GEEKOM", "Air13", "1.05", Hardware{"geekom", Unlisted, Unlisted}},
		{"Acme", "Box 1", "1.05", Hardware{"acme", "box_1", Unlisted}},
		{"Acme Inc.", "Box 1", "1.05", Hardware{Unlisted, Unlisted, Unlisted}},
		{"To Be Filled By O.E.M.", "To Be Filled By O.E.M.", "1.05", Hardware{Unlisted, Unlisted, Unlisted}},
		{"-", "Air12 Lite", "1.05", Hardware{Unlisted, Unlisted, Unlisted}},
		{"", "", "", Hardware{Unlisted, Unlisted, Unlisted}},
		{"géekom", "Air12 Lite", "1.05", Hardware{Unlisted, Unlisted, Unlisted}},
		{"unlisted", "unlisted", "unlisted", Hardware{Unlisted, Unlisted, Unlisted}},
		{"GEEKOM\x00", "Air12 Lite", "1.05", Hardware{Unlisted, Unlisted, Unlisted}},
		{strings.Repeat("geekom", 50), "Air12 Lite", "1.05", Hardware{Unlisted, Unlisted, Unlisted}},
	} {
		h, _, err := s.Measure(dmi(c.vendor, c.model, c.firmware), nil)
		if err != nil {
			t.Fatalf("%q/%q/%q: %v", c.vendor, c.model, c.firmware, err)
		}
		if h != c.want {
			t.Fatalf("%q/%q/%q measured %+v, want %+v", c.vendor, c.model, c.firmware, h, c.want)
		}
		if err := s.CheckHardware(h); err != nil {
			t.Fatalf("%q/%q/%q: measured hardware does not pass the strict check: %v", c.vendor, c.model, c.firmware, err)
		}
	}
	// No DMI at all (a VM without it, or an unreadable directory).
	if h, _, err := s.Measure(fstest.MapFS{}, nil); err != nil || h != (Hardware{Unlisted, Unlisted, Unlisted}) {
		t.Fatalf("no DMI: %+v %v", h, err)
	}
	// An oversized file is not read past its bound and counts as unlisted.
	big := dmi("GEEKOM", "Air12 Lite", "1.05")
	big[DMIModel] = &fstest.MapFile{Data: []byte("Air12 Lite" + strings.Repeat(" ", MaxDMIBytes) + "x")}
	if h, _, _ := s.Measure(big, nil); h != (Hardware{"geekom", Unlisted, Unlisted}) {
		t.Fatalf("oversized model: %+v", h)
	}
}

// TestOSS8MeasureReportsEveryListedComponentTheReleaseInstalls (A9): the
// versions are the installed release's, and the set of components is
// always every listed component the release installs, whatever their
// versions; a version the schema does not list is Unlisted, a component it
// does not list is left out, so which components appear never depends on
// anything but the release and the schema.
func TestOSS8MeasureReportsEveryListedComponentTheReleaseInstalls(t *testing.T) {
	s := measureSchema(t)
	installs := map[string]string{"openclaw": "2026.9.8", "node": "24.22.0", "kernel": "6.12.48", "chromium": "140.0.7339.80"}
	_, vs, err := s.Measure(dmi("GEEKOM", "Air12 Lite", "1.05"), installs)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"openclaw": "2026.9.8", "node": Unlisted, "chromium": "140.0.7339.80"}
	if !maps.Equal(vs, want) {
		t.Fatalf("versions %v, want %v", vs, want)
	}
	if err := s.CheckVersions(vs); err != nil {
		t.Fatal("measured versions do not pass the strict check:", err)
	}
	keys := slices.Sorted(maps.Keys(vs))
	for _, v := range []string{"0", "2026.9.8", "Not A Token", "", strings.Repeat("9", 40)} {
		alt := maps.Clone(installs)
		for c := range alt {
			alt[c] = v
		}
		_, got, err := s.Measure(dmi("GEEKOM", "Air12 Lite", "1.05"), alt)
		if err != nil {
			t.Fatalf("versions all %q: %v", v, err)
		}
		if k := slices.Sorted(maps.Keys(got)); !slices.Equal(k, keys) {
			t.Fatalf("versions all %q changed the components reported: %v, want %v", v, k, keys)
		}
		if err := s.CheckVersions(got); err != nil {
			t.Fatalf("versions all %q: %v", v, err)
		}
	}
	// A release that installs nothing listed reports no versions.
	if _, vs, err := s.Measure(dmi("-", "-", "-"), map[string]string{"kernel": "6.12.48"}); err != nil || len(vs) != 0 {
		t.Fatalf("nothing listed: %v %v", vs, err)
	}
	// A manifest naming more components than a statement may carry is refused.
	huge := map[string]string{}
	for i := range MaxComponents + 1 {
		huge[fmt.Sprintf("c%d", i)] = "1"
	}
	if _, _, err := s.Measure(dmi("-", "-", "-"), huge); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%d components: %v", len(huge), err)
	}
}

// TestOSS4MeasureIsAFunctionOfItsInputs (A9): two measurements of the same
// DMI data and release are identical, so nothing but measurement picks a
// listed value.
func TestOSS4MeasureIsAFunctionOfItsInputs(t *testing.T) {
	s := measureSchema(t)
	installs := map[string]string{"openclaw": "2026.9.8", "node": "24.21.0"}
	h1, v1, err1 := s.Measure(dmi("GEEKOM", "Air12 Lite", "2.0"), installs)
	for range 20 {
		h2, v2, err2 := s.Measure(dmi("GEEKOM", "Air12 Lite", "2.0"), installs)
		if h1 != h2 || !maps.Equal(v1, v2) || (err1 == nil) != (err2 == nil) {
			t.Fatalf("measurements differ: %+v %v / %+v %v", h1, v1, h2, v2)
		}
	}
	// The default schema measures the floor reference PC (HW-4).
	if h, _, err := Default().Measure(dmi("GEEKOM", "Air12 Lite", "1.05"), nil); err != nil || h != (Hardware{"geekom", "air12_lite", Unlisted}) {
		t.Fatalf("floor PC under the shipped schema: %+v %v", h, err)
	}
}
