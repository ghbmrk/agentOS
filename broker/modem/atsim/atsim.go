// Package atsim simulates a USB LTE modem at its AT port, so the real driver
// (broker/modem/at) runs in tests without hardware. Texts travel on the P1-5
// carrier simulator (broker/modem): the simulated modem is one Line on it.
// Calls and their audio are simulated here.
//
// Each vendor dialect follows its AT manual: Quectel needs the UAC flag and
// AT+QPCMV=1,2 before call audio flows on the sound card; SIMCom takes
// AT+CPCMREG=1 only once a call is connected and then streams PCM on the
// audio port. Commands of the other vendor answer ERROR. S2 on real modems
// checks these readings (broker/modem/at/S2-CONFIRM.md).
package atsim

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
)

// Device is one simulated modem.
type Device struct {
	prof  *at.Profile
	model string
	line  *modem.Line
	tick  time.Duration

	host, dev net.Conn // AT port: driver end, device end
	wmu       sync.Mutex

	mu       sync.Mutex
	echo     bool
	pduMode  bool
	cnmi     bool
	clip     bool
	keysURC  bool
	uac      bool
	pcmv     bool
	cpcmreg  bool
	muteCMTI bool
	store    map[int]string
	nextIdx  int
	outParts map[string]map[int]string
	call     *Far
	nextCall int
	outgoing chan *Far
	cmds     []string
	closed   bool
	upW      net.Conn // device end carrying the uplink (SIMCom port or Quectel capture)
}

// New attaches a simulated modem of profile p to a carrier line. model is
// what AT+CGMM answers; tick paces the audio stream (one 20 ms frame per
// tick).
func New(p *at.Profile, model string, line *modem.Line, tick time.Duration) *Device {
	host, dev := net.Pipe()
	d := &Device{prof: p, model: model, line: line, tick: tick, host: host, dev: dev, echo: true,
		store: map[int]string{}, outParts: map[string]map[int]string{}, outgoing: make(chan *Far, 4), nextCall: 1}
	go d.serve()
	go d.receive()
	go d.stream()
	return d
}

// Port is the driver's end of the AT port.
func (d *Device) Port() io.ReadWriteCloser { return d.host }

// Commands returns every command line the driver sent, in order.
func (d *Device) Commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.cmds...)
}

// SetUAC sets the Quectel UAC flag as if configured earlier.
func (d *Device) SetUAC(on bool) { d.mu.Lock(); d.uac = on; d.mu.Unlock() }

// UAC reports the Quectel UAC flag.
func (d *Device) UAC() bool { d.mu.Lock(); defer d.mu.Unlock(); return d.uac }

// MuteCMTI suppresses new-text notifications, as when a URC is lost.
func (d *Device) MuteCMTI(on bool) { d.mu.Lock(); d.muteCMTI = on; d.mu.Unlock() }

// Stored returns how many texts are in the modem's memory.
func (d *Device) Stored() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.store) }

// StorePDU puts a raw SMS-DELIVER PDU in memory and announces it.
func (d *Device) StorePDU(pdu string) {
	d.mu.Lock()
	i := d.nextIdx
	d.nextIdx++
	d.store[i] = pdu
	notify := d.cnmi && !d.muteCMTI
	d.mu.Unlock()
	if notify {
		d.urc(fmt.Sprintf(`+CMTI: "ME",%d`, i))
	}
}

// Unplug closes the port, as when the modem is pulled or restarts.
func (d *Device) Unplug() {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	_ = d.dev.Close()
}

func (d *Device) write(s string) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	_, _ = io.WriteString(d.dev, s)
}

func (d *Device) urc(l string) { d.write("\r\n" + l + "\r\n") }

func (d *Device) reply(lines ...string) {
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString("\r\n" + l + "\r\n")
	}
	d.write(sb.String())
}

// receive turns texts arriving on the carrier into stored PDUs.
func (d *Device) receive() {
	var ref byte
	for m := range d.line.Inbox() {
		ref++
		pdus, err := at.EncodeDeliver(m.From, m.Text, ref)
		if err != nil {
			continue
		}
		for _, p := range pdus {
			d.StorePDU(p)
		}
	}
}

func (d *Device) serve() {
	br := bufio.NewReader(d.dev)
	for {
		l, err := br.ReadString('\r')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(l)
		if cmd == "" {
			continue
		}
		d.mu.Lock()
		d.cmds = append(d.cmds, cmd)
		echo := d.echo
		d.mu.Unlock()
		if echo {
			d.write(cmd + "\r")
		}
		if strings.HasPrefix(cmd, "AT+CMGS=") {
			d.cmgs(br, cmd)
			continue
		}
		d.reply(d.handle(cmd)...)
	}
}

func (d *Device) cmgs(br *bufio.Reader, cmd string) {
	n, err := strconv.Atoi(strings.TrimPrefix(cmd, "AT+CMGS="))
	d.mu.Lock()
	pdu := d.pduMode
	d.mu.Unlock()
	if err != nil || !pdu {
		d.reply("ERROR")
		return
	}
	d.write("\r\n> ")
	payload, err := br.ReadString(0x1A)
	if err != nil {
		return
	}
	payload = strings.TrimSuffix(payload, "\x1a")
	if i := strings.IndexByte(payload, 0x1B); i >= 0 {
		d.reply("OK") // cancelled
		return
	}
	if len(payload)/2-1 != n {
		d.reply("+CMS ERROR: 304")
		return
	}
	s, err := at.DecodeSubmit(payload)
	if err != nil {
		d.reply("+CMS ERROR: 304")
		return
	}
	text, done := s.Text, true
	if s.Concat != nil && s.Concat.Total > 1 {
		d.mu.Lock()
		key := fmt.Sprintf("%s/%d", s.Addr, s.Concat.Ref)
		if d.outParts[key] == nil {
			d.outParts[key] = map[int]string{}
		}
		d.outParts[key][s.Concat.Seq] = s.Text
		if len(d.outParts[key]) == s.Concat.Total {
			var sb strings.Builder
			for i := 1; i <= s.Concat.Total; i++ {
				sb.WriteString(d.outParts[key][i])
			}
			text = sb.String()
			delete(d.outParts, key)
		} else {
			done = false
		}
		d.mu.Unlock()
	}
	if done {
		if err := d.line.Send(s.Addr, text); err != nil {
			d.reply("+CMS ERROR: 331")
			return
		}
	}
	d.reply("+CMGS: 1", "OK")
}

func (d *Device) handle(cmd string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	quectel, simcom := d.prof == at.Quectel, d.prof == at.SIMCom
	switch {
	case cmd == "AT", cmd == "AT+CMEE=1", cmd == "AT+CNMI=2,1,0,0,0" && d.setCNMI():
		return []string{"OK"}
	case cmd == "ATE0":
		d.echo = false
		return []string{"OK"}
	case cmd == "AT+CGMM":
		return []string{d.model, "OK"}
	case cmd == "AT+CMGF=0":
		d.pduMode = true
		return []string{"OK"}
	case strings.HasPrefix(cmd, "AT+CPMS="):
		return []string{"+CPMS: 0,100,0,100,0,100", "OK"}
	case cmd == "AT+CLIP=1":
		d.clip = true
		return []string{"OK"}
	case cmd == "AT+CNUM":
		return []string{fmt.Sprintf(`+CNUM: "","%s",145`, d.line.Number()), "OK"}
	case strings.HasPrefix(cmd, "AT+CMGR="):
		i, _ := strconv.Atoi(strings.TrimPrefix(cmd, "AT+CMGR="))
		p, ok := d.store[i]
		if !ok {
			return []string{"+CMS ERROR: 321"}
		}
		return []string{fmt.Sprintf("+CMGR: 0,,%d", len(p)/2-8), p, "OK"}
	case strings.HasPrefix(cmd, "AT+CMGD="):
		i, _ := strconv.Atoi(strings.TrimPrefix(cmd, "AT+CMGD="))
		delete(d.store, i)
		return []string{"OK"}
	case cmd == "AT+CMGL=4":
		var idx []int
		for i := range d.store {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		var out []string
		for _, i := range idx {
			out = append(out, fmt.Sprintf("+CMGL: %d,0,,%d", i, len(d.store[i])/2-8), d.store[i])
		}
		return append(out, "OK")
	case strings.HasPrefix(cmd, "ATD") && strings.HasSuffix(cmd, ";"):
		if d.call != nil {
			return []string{"ERROR"}
		}
		f := d.newCallLocked(strings.TrimSuffix(strings.TrimPrefix(cmd, "ATD"), ";"), false, 2)
		go func() {
			time.Sleep(time.Millisecond)
			d.mu.Lock()
			if d.call == f && f.stat == 2 {
				f.stat = 3
			}
			d.mu.Unlock()
			d.outgoing <- f
		}()
		return []string{"OK"}
	case cmd == "ATA":
		if d.call == nil || d.call.stat != 4 {
			return []string{"NO CARRIER"}
		}
		d.call.stat = 0
		if simcom {
			go d.urc("VOICE CALL: BEGIN")
		}
		return []string{"OK"}
	case cmd == "AT+CHUP", cmd == "ATH":
		if d.call != nil {
			d.endLocked()
		}
		return []string{"OK"}
	case cmd == "AT+CLCC":
		if d.call == nil {
			return []string{"OK"}
		}
		dir := 0
		if d.call.incoming {
			dir = 1
		}
		return []string{fmt.Sprintf(`+CLCC: %d,%d,%d,0,0,"%s",145`, d.call.id, dir, d.call.stat, d.call.Number), "OK"}
	// Quectel
	case quectel && cmd == `AT+QURCCFG="urcport","usbat"`:
		return []string{"OK"}
	case quectel && cmd == "AT+QPCMV=1,2":
		d.pcmv = true
		return []string{"OK"}
	case quectel && cmd == "AT+QPCMV=0":
		d.pcmv = false
		return []string{"OK"}
	case quectel && cmd == "AT+QTONEDET=1":
		d.keysURC = true
		return []string{"OK"}
	case quectel && cmd == `AT+QCFG="usbcfg"`:
		u := 0
		if d.uac {
			u = 1
		}
		return []string{fmt.Sprintf(`+QCFG: "usbcfg",0x2C7C,0x0125,1,1,1,1,1,0,%d`, u), "OK"}
	case quectel && strings.HasPrefix(cmd, `AT+QCFG="usbcfg",`):
		f := strings.Split(strings.TrimPrefix(cmd, `AT+QCFG="usbcfg",`), ",")
		if len(f) != 9 {
			return []string{"ERROR"}
		}
		d.uac = f[8] == "1"
		return []string{"OK"}
	case quectel && cmd == "AT+CFUN=1,1":
		go func() { time.Sleep(10 * time.Millisecond); d.Unplug() }()
		return []string{"OK"}
	// SIMCom
	case simcom && cmd == "AT+CPCMFRM=0":
		return []string{"OK"}
	case simcom && cmd == "AT+CPCMREG=1":
		if d.call == nil || d.call.stat != 0 {
			return []string{"ERROR"} // only during a connected call
		}
		d.cpcmreg = true
		return []string{"OK"}
	case simcom && cmd == "AT+CPCMREG=0":
		d.cpcmreg = false
		return []string{"OK"}
	case simcom && cmd == "AT+DDET=1":
		d.keysURC = true
		return []string{"OK"}
	}
	return []string{"ERROR"}
}

func (d *Device) setCNMI() bool { d.cnmi = true; return true }

// ---- calls ----

// Far is the far end of a simulated call.
type Far struct {
	d        *Device
	id       int
	Number   string
	incoming bool
	stat     int // +CLCC stat: 0 active, 2 dialing, 3 alerting, 4 incoming
	up       []byte
	heard    []byte
	ended    bool
}

func (d *Device) newCallLocked(number string, incoming bool, stat int) *Far {
	f := &Far{d: d, id: d.nextCall, Number: number, incoming: incoming, stat: stat}
	d.nextCall++
	d.call = f
	return f
}

func (d *Device) endLocked() {
	d.call.ended = true
	d.call = nil
	d.pcmv, d.cpcmreg = d.pcmv && d.prof == at.Quectel, false
	if d.prof == at.SIMCom {
		go d.urc("VOICE CALL: END: 000010")
	}
	go d.urc("NO CARRIER")
}

// Ring places an incoming call from number.
func (d *Device) Ring(from string) *Far {
	d.mu.Lock()
	f := d.newCallLocked(from, true, 4)
	clip := d.clip
	d.mu.Unlock()
	d.urc("RING")
	if clip {
		d.urc(fmt.Sprintf(`+CLIP: "%s",145,,,,0`, from))
	}
	return f
}

// Outgoing delivers calls the driver dialed.
func (d *Device) Outgoing() <-chan *Far { return d.outgoing }

// Answer connects a call the box dialed.
func (f *Far) Answer() {
	f.d.mu.Lock()
	ok := f.d.call == f && !f.incoming
	if ok {
		f.stat = 0
	}
	f.d.mu.Unlock()
	if ok && f.d.prof == at.SIMCom {
		f.d.urc("VOICE CALL: BEGIN")
	}
}

// Hangup ends the call from the far end.
func (f *Far) Hangup() {
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	if f.d.call == f {
		f.d.endLocked()
	}
}

// Active reports whether the call is connected.
func (f *Far) Active() bool { f.d.mu.Lock(); defer f.d.mu.Unlock(); return f.stat == 0 && !f.ended }

// Ended reports whether the call is over.
func (f *Far) Ended() bool { f.d.mu.Lock(); defer f.d.mu.Unlock(); return f.ended }

// Say queues the far end's voice (8 kHz S16_LE mono) toward the box.
func (f *Far) Say(pcm []byte) {
	f.d.mu.Lock()
	f.up = append(f.up, pcm...)
	f.d.mu.Unlock()
}

// Press sends keypad presses: tones in the audio, and the vendor's DTMF
// report when the driver turned it on.
func (f *Far) Press(keys string) {
	for i := 0; i < len(keys); i++ {
		f.Say(Tone(keys[i], 120, 120))
		f.d.mu.Lock()
		on := f.d.keysURC
		f.d.mu.Unlock()
		if on {
			if f.d.prof == at.Quectel {
				f.d.urc(fmt.Sprintf("+QTONEDET: %d", keys[i]))
			} else {
				f.d.urc(fmt.Sprintf("+RXDTMF: %c", keys[i]))
			}
		}
	}
}

// Heard returns the audio the box sent to the far end.
func (f *Far) Heard() []byte {
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	return append([]byte(nil), f.heard...)
}

// Pending reports how much queued far-end audio has not yet been streamed.
func (f *Far) Pending() int { f.d.mu.Lock(); defer f.d.mu.Unlock(); return len(f.up) }

// ---- audio ----

// SerialAudio opens the SIMCom audio port. Each open replaces the last.
func (d *Device) SerialAudio() (io.ReadWriteCloser, error) {
	if d.prof != at.SIMCom {
		return nil, fmt.Errorf("atsim: no audio port on %s", d.prof.Name)
	}
	host, dev := net.Pipe()
	d.mu.Lock()
	if d.upW != nil {
		_ = d.upW.Close()
	}
	d.upW = dev
	d.mu.Unlock()
	go d.drain(dev)
	return host, nil
}

// Runner is the Quectel sound card: capture carries the uplink and
// playback the downlink.
func (d *Device) Runner() at.Runner { return uacRunner{d} }

type uacRunner struct{ d *Device }

func (r uacRunner) Record(_ context.Context, card string) (io.ReadCloser, error) {
	if r.d.prof != at.Quectel || !r.d.UAC() || card != Card {
		return nil, fmt.Errorf("atsim: no sound card %q", card)
	}
	host, dev := net.Pipe()
	r.d.mu.Lock()
	if r.d.upW != nil {
		_ = r.d.upW.Close()
	}
	r.d.upW = dev
	r.d.mu.Unlock()
	go func() { _, _ = io.Copy(io.Discard, dev) }()
	return host, nil
}

func (r uacRunner) Play(_ context.Context, card string) (io.WriteCloser, error) {
	if r.d.prof != at.Quectel || !r.d.UAC() || card != Card {
		return nil, fmt.Errorf("atsim: no sound card %q", card)
	}
	host, dev := net.Pipe()
	go r.d.drain(dev)
	return host, nil
}

// Card is the simulated Quectel sound card number.
const Card = "1"

func (d *Device) routedLocked() bool {
	if d.call == nil || d.call.stat != 0 {
		return false
	}
	if d.prof == at.Quectel {
		return d.uac && d.pcmv
	}
	return d.cpcmreg
}

// stream writes the uplink one frame per tick while audio is routed:
// queued far-end audio, else silence.
func (d *Device) stream() {
	t := time.NewTicker(d.tick)
	defer t.Stop()
	silence := make([]byte, at.FrameBytes)
	for range t.C {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return
		}
		w := d.upW
		if !d.routedLocked() {
			w = nil
		}
		frame := silence
		if w != nil && len(d.call.up) > 0 {
			n := min(at.FrameBytes, len(d.call.up))
			frame = append(append([]byte(nil), d.call.up[:n]...), silence[n:]...)
			d.call.up = d.call.up[n:]
		}
		d.mu.Unlock()
		if w != nil {
			_ = w.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = w.Write(frame)
		}
	}
}

// drain reads the downlink; it reaches the far end only while routed.
func (d *Device) drain(r io.Reader) {
	buf := make([]byte, at.FrameBytes)
	for {
		n, err := r.Read(buf)
		if err != nil {
			return
		}
		d.mu.Lock()
		if d.routedLocked() {
			d.call.heard = append(d.call.heard, buf[:n]...)
		}
		d.mu.Unlock()
	}
}

// Tone synthesizes one keypad press and a silence gap, as dtmf.py does.
func Tone(key byte, ms, gapMs int) []byte {
	rows := []float64{697, 770, 852, 941}
	cols := []float64{1209, 1336, 1477, 1633}
	keys := []string{"123A", "456B", "789C", "*0#D"}
	var r, c int
	for i, row := range keys {
		if j := strings.IndexByte(row, key); j >= 0 {
			r, c = i, j
		}
	}
	n := at.Rate * ms / 1000
	out := make([]byte, 0, 2*(n+at.Rate*gapMs/1000))
	for t := 0; t < n; t++ {
		v := 8000 * (math.Sin(2*math.Pi*rows[r]*float64(t)/at.Rate) + math.Sin(2*math.Pi*cols[c]*float64(t)/at.Rate)) / 2
		s := uint16(int16(v))
		out = append(out, byte(s), byte(s>>8))
	}
	return append(out, make([]byte, 2*at.Rate*gapMs/1000)...)
}
