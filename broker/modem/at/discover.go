package at

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Found is one qualified modem on the USB bus.
type Found struct {
	Profile *Profile
	// USB is the device's sysfs name, e.g. "1-2".
	USB string
	// ATPort and AudioPort are /dev paths ("" when absent).
	ATPort, AudioPort string
	// Card is the ALSA card number of a UAC modem ("" until EnsureUAC has
	// taken effect).
	Card string
}

// Discover lists qualified modems from sysfs and procfs under root ("/"
// outside tests). Modems of other vendors are skipped.
func Discover(root string) []Found {
	byDev := map[string]*Found{}
	ttys, _ := filepath.Glob(filepath.Join(root, "sys/bus/usb-serial/devices/ttyUSB*"))
	for _, tty := range ttys {
		real, err := filepath.EvalSymlinks(tty)
		if err != nil {
			continue
		}
		intf := filepath.Dir(real) // .../1-2/1-2:1.2/ttyUSB2
		dev := filepath.Dir(intf)  // .../1-2
		p := ProfileFor(readTrim(filepath.Join(dev, "idVendor")))
		if p == nil {
			continue
		}
		f := byDev[dev]
		if f == nil {
			f = &Found{Profile: p, USB: filepath.Base(dev)}
			byDev[dev] = f
		}
		node := filepath.Join(root, "dev", filepath.Base(tty))
		switch readTrim(filepath.Join(intf, "bInterfaceNumber")) {
		case p.ATInterface:
			f.ATPort = node
		case p.AudioInterface:
			if p.AudioInterface != "" {
				f.AudioPort = node
			}
		}
		if p.Audio == AudioUAC && f.Card == "" {
			f.Card = uacCard(root, dev)
		}
	}
	out := make([]Found, 0, len(byDev))
	for _, f := range byDev {
		if f.ATPort != "" {
			out = append(out, *f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].USB < out[j].USB })
	return out
}

// uacCard finds the ALSA card on the same USB device, matched by bus and
// device number so two modems of one vendor never swap audio.
func uacCard(root, dev string) string {
	want := padBusDev(readTrim(filepath.Join(dev, "busnum")), readTrim(filepath.Join(dev, "devnum")))
	cards, _ := filepath.Glob(filepath.Join(root, "proc/asound/card*/usbbus"))
	for _, c := range cards {
		if readTrim(c) == want {
			return strings.TrimPrefix(filepath.Base(filepath.Dir(c)), "card")
		}
	}
	return ""
}

func padBusDev(bus, dev string) string {
	pad := func(s string) string {
		for len(s) < 3 {
			s = "0" + s
		}
		return s
	}
	return pad(bus) + "/" + pad(dev)
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
