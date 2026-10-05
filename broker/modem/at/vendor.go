package at

import (
	"strconv"
	"strings"
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
	URCs:     []string{"+QTONEDET:", "+QIND:"},
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
	URCs:           []string{"+RXDTMF:", "VOICE CALL:", "MISSED_CALL:"},
	CallURCs:       []string{"VOICE CALL:", "MISSED_CALL:"},
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
