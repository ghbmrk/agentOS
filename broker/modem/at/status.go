package at

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// SIMState is what AT+CPIN? says about the SIM.
type SIMState int

const (
	SIMUnknown SIMState = iota
	SIMReady
	// SIMMissing: no SIM, or one the modem cannot read.
	SIMMissing
	// SIMLocked: the SIM wants a PIN or PUK. The box never asks for one
	// over text or voice (CH-6); the owner removes the PIN in a phone.
	SIMLocked
)

// RegState is network registration (AT+CEREG? for LTE, AT+CREG? for
// circuit-switched), the better of the two.
type RegState int

const (
	RegUnknown RegState = iota
	RegNone             // not searching
	RegSearching
	RegDenied
	RegHome
	RegRoaming
)

// Status is the SIM, network and signal as last read. The local UI (P2-2)
// shows Line; nothing in it identifies the SIM or the owner.
type Status struct {
	SIM SIMState
	Reg RegState
	// Bars is signal strength from 0 to 4 (AT+CSQ).
	Bars int
}

// Registered reports whether texts and calls can work.
func (s Status) Registered() bool { return s.Reg == RegHome || s.Reg == RegRoaming }

// Line is one plain sentence for the owner.
func (s Status) Line() string {
	switch {
	case s.SIM == SIMMissing:
		return "No SIM found. Check it is in the modem."
	case s.SIM == SIMLocked:
		return "The SIM is PIN-locked. Remove the PIN in a phone, then put it back."
	case s.Reg == RegDenied:
		return "The carrier refused the SIM. Check it is activated."
	case s.Registered() && s.Reg == RegRoaming:
		return fmt.Sprintf("Connected to a partner network (roaming), signal %d of 4.", s.Bars)
	case s.Registered():
		return fmt.Sprintf("Connected to the mobile network, signal %d of 4.", s.Bars)
	case s.Bars == 0:
		return "No mobile signal here. Move the box nearer a window."
	default:
		return "Looking for the mobile network."
	}
}

// SIMError is returned by Open when the SIM is missing or locked, so the
// caller can show Status.Line and try again once the owner has fixed it.
type SIMError struct{ Status Status }

func (e *SIMError) Error() string { return "at: " + e.Status.Line() }

// readSIM parses AT+CPIN?.
func (m *Modem) readSIM(ctx context.Context) SIMState {
	lines, err := m.e.Do(ctx, "AT+CPIN?", cmdTimeout)
	if err != nil {
		if ae, ok := err.(*Error); ok && strings.HasPrefix(ae.Result, "+CME ERROR") {
			// 10 not inserted, 13 failure, 14 busy: none is a usable SIM.
			return SIMMissing
		}
		return SIMUnknown
	}
	for _, l := range lines {
		v := strings.TrimSpace(strings.TrimPrefix(l, "+CPIN:"))
		switch {
		case v == "READY":
			return SIMReady
		case strings.HasPrefix(v, "SIM PIN"), strings.HasPrefix(v, "SIM PUK"), strings.HasPrefix(v, "PH-"):
			return SIMLocked
		case v != "":
			return SIMMissing
		}
	}
	return SIMUnknown
}

// readStatus refreshes SIM, registration and signal.
func (m *Modem) readStatus(ctx context.Context) Status {
	s := Status{SIM: m.readSIM(ctx)}
	if s.SIM == SIMReady {
		s.Reg = max(m.readReg(ctx, "AT+CEREG?"), m.readReg(ctx, "AT+CREG?"))
		s.Bars = m.readBars(ctx)
	}
	m.mu.Lock()
	m.status = s
	m.mu.Unlock()
	return s
}

func (m *Modem) readReg(ctx context.Context, cmd string) RegState {
	lines, err := m.e.Do(ctx, cmd, cmdTimeout)
	if err != nil {
		return RegUnknown
	}
	for _, l := range lines {
		f := fields(l[strings.IndexByte(l, ':')+1:])
		if len(f) < 2 {
			continue
		}
		switch f[1] {
		case "0":
			return RegNone
		case "1":
			return RegHome
		case "2":
			return RegSearching
		case "3":
			return RegDenied
		case "5":
			return RegRoaming
		}
	}
	return RegUnknown
}

func (m *Modem) readBars(ctx context.Context) int {
	lines, err := m.e.Do(ctx, "AT+CSQ", cmdTimeout)
	if err != nil {
		return 0
	}
	for _, l := range lines {
		f := fields(strings.TrimPrefix(l, "+CSQ:"))
		rssi, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		switch {
		case rssi == 99 || rssi < 2:
			return 0
		case rssi < 10:
			return 1
		case rssi < 15:
			return 2
		case rssi < 20:
			return 3
		default:
			return 4
		}
	}
	return 0
}

// Status returns the SIM, network and signal as last read: at Open, on
// every registration or SIM notice from the modem, and at each sweep.
func (m *Modem) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// readICCID reads the SIM's serial number, which binds a SIM to its role
// (owner line or second line) whatever USB port the modem is in.
func (m *Modem) readICCID(ctx context.Context) string {
	for _, cmd := range []string{m.cfg.Profile.ICCIDCmd, "AT+CCID"} {
		if cmd == "" {
			continue
		}
		lines, err := m.e.Do(ctx, cmd, cmdTimeout)
		if err != nil {
			continue
		}
		for _, l := range lines {
			if i := strings.IndexByte(l, ':'); i >= 0 {
				l = l[i+1:]
			}
			v := strings.Trim(strings.TrimSpace(l), `"`)
			if len(v) >= 18 && len(v) <= 22 && isICCID(v) {
				return strings.ToUpper(v)
			}
		}
	}
	return ""
}

func isICCID(v string) bool {
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c == 'F' || c == 'f') {
			return false
		}
	}
	return true
}

// ICCID is the SIM's serial number ("" when unreadable). It identifies the
// SIM and is kept in the broker's configuration only; never log it.
func (m *Modem) ICCID() string { return m.iccid }
