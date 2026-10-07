package attest

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// DMI is where Linux shows the firmware's SMBIOS identity, one value per
// file. Measure reads these three files and no others.
const (
	DMIDir      = "/sys/class/dmi/id"
	DMIVendor   = "sys_vendor"
	DMIModel    = "product_name"
	DMIFirmware = "bios_version"
)

// MaxDMIBytes bounds one DMI value. A longer file is not a value any
// schema lists, so it is measured as Unlisted without reading further.
const MaxDMIBytes = 256

// Measure fills an attestation's hardware and versions from measurement
// alone (A9, security C2 on #73): hardware from the DMI files in dmi (the
// box passes os.DirFS(DMIDir)), versions from the components the installed
// release installs (installs, from its signed manifest). No agent or owner
// input reaches it, so which listed value a statement names carries no
// choice anyone could use to encode bits.
//
// A measured value is normalised to the schema's token form (MeasuredToken)
// and kept only if the schema lists it under the level above; otherwise it
// is Unlisted, and so is every level below it. A missing, unreadable,
// oversized or non-printable value is Unlisted too. Versions hold exactly
// the listed components the release installs, each at its version if
// listed, else Unlisted; components the schema does not list are left out.
// So the set of components reported depends only on the release and the
// schema. A manifest naming more than MaxComponents components is
// refused.
func (s *Schema) Measure(dmi fs.FS, installs map[string]string) (Hardware, map[string]string, error) {
	if len(installs) > MaxComponents {
		return Hardware{}, nil, fmt.Errorf("%w: the release installs %d components, over %d", ErrInvalid, len(installs), MaxComponents)
	}
	h := Hardware{Unlisted, Unlisted, Unlisted}
	if v := MeasuredToken(readDMI(dmi, DMIVendor)); s.hardware[v] != nil {
		h.Vendor = v
		if m := MeasuredToken(readDMI(dmi, DMIModel)); s.hardware[v][m] != nil {
			h.Model = m
			if f := MeasuredToken(readDMI(dmi, DMIFirmware)); s.hardware[v][m][f] {
				h.Firmware = f
			}
		}
	}
	var vs map[string]string
	for c, v := range installs {
		allowed, ok := s.versions[c]
		if !ok {
			continue
		}
		if !allowed[v] {
			v = Unlisted
		}
		if vs == nil {
			vs = map[string]string{}
		}
		vs[c] = v
	}
	return h, vs, nil
}

// readDMI returns one DMI value, or "" when the file is missing,
// unreadable or longer than MaxDMIBytes.
func readDMI(dmi fs.FS, name string) string {
	f, err := dmi.Open(name)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxDMIBytes+1))
	if err != nil || len(b) > MaxDMIBytes {
		return ""
	}
	return string(b)
}

// MeasuredToken normalises a raw DMI value to the form the schema lists:
// surrounding space trimmed, ASCII letters lower-cased, every run of other
// characters but digits, '.' and '-' turned into one '_', and leading or
// trailing '_', '.' and '-' dropped ("Air12 Lite" is air12_lite). A value
// holding a control character or a non-ASCII byte, or one that does not
// end up a token, gives "", which no schema lists.
func MeasuredToken(raw string) string {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	sep := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c < 0x20 || c >= 0x7f:
			return ""
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
			fallthrough
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '.', c == '-':
			if sep {
				b.WriteByte('_')
				sep = false
			}
			b.WriteByte(c)
		default:
			sep = b.Len() > 0
		}
	}
	t := strings.Trim(b.String(), "_.-")
	if !token.MatchString(t) {
		return ""
	}
	return t
}
