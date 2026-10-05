package at

import (
	"strconv"
	"strings"
	"time"
)

// AudioKind is how a modem carries call audio to the host.
type AudioKind int

const (
	// AudioUAC is USB Audio Class: the modem appears as an ALSA card.
	AudioUAC AudioKind = iota + 1
	// AudioSerial is raw PCM on a dedicated USB serial interface.
	AudioSerial
)

// Profile is one qualified modem family (HW-2: qualify specific models).
// Commands and interface numbers come from the vendors' AT manuals and the
// S2 test kit; S2 on real hardware confirms them (see S2-CONFIRM.md).
type Profile struct {
	Name string
	// USBVendor is the USB idVendor, lower-case hex.
	USBVendor string
	// Models are AT+CGMM prefixes this profile accepts. Open refuses any
	// other model rather than sending it another vendor's commands.
	Models []string
	// ATInterface and AudioInterface are USB bInterfaceNumber values.
	ATInterface, AudioInterface string
	Audio                       AudioKind
	// Init runs after the common setup; every command must succeed.
	Init []string
	// AudioOn runs once a call is active, AudioOff when it ends.
	AudioOn, AudioOff []string
	// KeysOn turns on the modem's own DTMF detection (KeysModem).
	KeysOn string
	// URCs are vendor result codes beyond TS 27.007's.
	URCs []string
	// CallURCs are the vendor URCs that change call state.
	CallURCs []string
	// Key parses the modem's DTMF URC.
	Key func(string) (byte, bool)
	// ICCIDCmd reads the SIM serial number (AT+CCID is the fallback).
	ICCIDCmd string
	// NetTimeCmd reads carrier network time (TIM-1), which NetTime parses
	// to UTC; ok is false when the network has sent none.
	// NetTimeOn, if set, runs at Open, best effort: a modem that refuses
	// it still texts and calls.
	NetTimeCmd string
	NetTime    func(lines []string) (t time.Time, ok bool)
	NetTimeOn  string
}

// Quectel covers the EC25 and EG25-G (S2 modem 1). Voice audio is USB Audio
// Class, which the module exposes only after the UAC flag is set in its USB
// composition (EnsureUAC); AT+QPCMV=1,2 routes call audio to it.
var Quectel = &Profile{
	Name:        "Quectel EC25/EG25",
	USBVendor:   "2c7c",
	Models:      []string{"EC25", "EG25"},
	ATInterface: "02",
	Audio:       AudioUAC,
	// URCs on the USB AT port, where the driver listens.
	Init:     []string{`AT+QURCCFG="urcport","usbat"`},
	AudioOn:  []string{"AT+QPCMV=1,2"},
	AudioOff: []string{"AT+QPCMV=0"},
	KeysOn:   "AT+QTONEDET=1",
	ICCIDCmd: "AT+QCCID",
	// AT+QLTS=1: UTC as of the latest network time update, carried on by
	// the module's clock; "" until the network has sent one.
	NetTimeCmd: "AT+QLTS=1",
	NetTime:    parseQLTS,
	URCs:       []string{"+QTONEDET:", "+QIND:"},
	Key: func(l string) (byte, bool) {
		v, ok := urcValue(l, "+QTONEDET:")
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(v) // ASCII code of the key
		if err != nil {
			return 0, false
		}
		return keyByte(byte(n))
	},
}

// SIMCom covers the SIM7600G-H (S2 modem 2). Voice audio is 8 kHz 16-bit
// PCM on USB interface 4 once AT+CPCMREG=1 is set during a call.
var SIMCom = &Profile{
	Name:           "SIMCom SIM7600G-H",
	USBVendor:      "1e0e",
	Models:         []string{"SIMCOM_SIM7600G-H", "SIM7600G-H"},
	ATInterface:    "02",
	AudioInterface: "04",
	Audio:          AudioSerial,
	Init:           []string{"AT+CPCMFRM=0"}, // 8 kHz PCM
	AudioOn:        []string{"AT+CPCMREG=1"},
	AudioOff:       []string{"AT+CPCMREG=0"},
	KeysOn:         "AT+DDET=1",
	ICCIDCmd:       "AT+CICCID",
	// AT+CCLK? is the module's clock, set from network time by AT+CTZU=1.
	// It has no "never set" answer: after power-up it starts from a fixed
	// date years in the past, which netTimeFloor rejects (S2-CONFIRM C14).
	NetTimeCmd: "AT+CCLK?",
	NetTime:    parseCCLK,
	NetTimeOn:  "AT+CTZU=1",
	URCs:       []string{"+RXDTMF:", "VOICE CALL:", "MISSED_CALL:", "+SIMCARD:"},
	CallURCs:   []string{"VOICE CALL:", "MISSED_CALL:"},
	Key: func(l string) (byte, bool) {
		v, ok := urcValue(l, "+RXDTMF:")
		if !ok || len(v) != 1 {
			return 0, false
		}
		return keyByte(v[0])
	},
}

// Profiles are the qualified modem families.
var Profiles = []*Profile{Quectel, SIMCom}

// ProfileFor returns the profile for a USB vendor ID, or nil.
func ProfileFor(usbVendor string) *Profile {
	for _, p := range Profiles {
		if strings.EqualFold(p.USBVendor, usbVendor) {
			return p
		}
	}
	return nil
}

func (p *Profile) accepts(model string) bool {
	m := strings.ToUpper(strings.TrimSpace(model))
	for _, x := range p.Models {
		if strings.HasPrefix(m, x) {
			return true
		}
	}
	return false
}

func urcValue(l, prefix string) (string, bool) {
	if !strings.HasPrefix(l, prefix) {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(l[len(prefix):]), `"`), true
}

func keyByte(b byte) (byte, bool) {
	if strings.IndexByte("0123456789*#ABCD", b) < 0 {
		return 0, false
	}
	return b, true
}

// netTimeFloor rejects a module clock that was never set from the network:
// both start from a fixed date long before this driver was written.
var netTimeFloor = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// parseQLTS reads +QLTS: "yyyy/MM/dd,hh:mm:ss±zz,dst" in mode 1 (UTC; the
// zone is the network's and is not needed).
func parseQLTS(lines []string) (time.Time, bool) {
	for _, l := range lines {
		v, ok := urcValue(l, "+QLTS:")
		if !ok {
			continue
		}
		if len(v) < 19 {
			return time.Time{}, false
		}
		t, err := time.Parse("2006/01/02,15:04:05", v[:19])
		if err != nil || t.Before(netTimeFloor) {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}

// parseCCLK reads +CCLK: "yy/MM/dd,hh:mm:ss±zz": local time with the zone
// in quarter hours east of UTC (TS 27.007).
func parseCCLK(lines []string) (time.Time, bool) {
	for _, l := range lines {
		v, ok := urcValue(l, "+CCLK:")
		if !ok {
			continue
		}
		if len(v) < 20 || (v[17] != '+' && v[17] != '-') {
			return time.Time{}, false
		}
		local, err := time.Parse("06/01/02,15:04:05", v[:17])
		z := v[18:]
		q, qerr := strconv.Atoi(z)
		if err != nil || qerr != nil || len(z) != 2 || z[0] < '0' || z[0] > '9' || z[1] < '0' || z[1] > '9' || q > 56 {
			return time.Time{}, false
		}
		if v[17] == '-' {
			q = -q
		}
		t := local.Add(-time.Duration(q) * 15 * time.Minute)
		if t.Before(netTimeFloor) {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}
