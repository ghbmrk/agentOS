// Package at is the real modem driver (PLAN P2-3): the box's SIM through a
// USB LTE modem's AT port, for texts (CH-1) and live calls (CH-5), on the two
// qualified families (HW-2): Quectel EC25/EG25 with USB Audio Class voice
// and SIMCom SIM7600G-H with PCM over serial.
//
// Modem implements modem.Modem, so the owner channel runs on it unchanged.
// Calls add Dial and Calls; each call decodes keypad presses in the broker
// and hands the speech side only audio with the tones cut out (CH-17).
package at

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// KeySource is where keypad presses during a call are read from.
type KeySource int

const (
	// KeysInBand decodes the tones in the call's uplink audio (the S2 kit's
	// method). It needs an audio route.
	KeysInBand KeySource = iota
	// KeysModem reads the modem's own DTMF reports (Profile.KeysOn). S2
	// decides whether VoLTE calls need it: when the network carries keys
	// out of band, the tones may never appear in the audio.
	KeysModem
)

// Config configures a Modem.
type Config struct {
	Profile *Profile
	// Port is the modem's AT interface (OpenSerial outside tests).
	Port io.ReadWriteCloser
	// Number is the SIM's own number, set at setup. AT+CNUM is tried when
	// it is empty, but many SIMs do not store their number.
	Number string
	// Audio opens call audio; nil means calls connect without audio.
	Audio AudioOpener
	Keys  KeySource
	Now   func() time.Time
	// FramePace paces downlink audio per 20 ms frame (default 20 ms).
	FramePace time.Duration
	// Poll is how often call state is re-read during calls (default 1 s).
	Poll time.Duration
	// Sweep is how often stored texts are re-read in case a +CMTI was
	// lost, and status re-read (default 30 s).
	Sweep time.Duration
	// CountryCode is the home country code from setup ("1", "44"), used to
	// write national-format numbers as E.164 so they match the owner's.
	CountryCode string
	// Owner is the owner's number when this SIM is the owner line. A long
	// text from it that arrives garbled (conflicting parts) gets the fixed
	// GarbledText reply, at most once an hour.
	Owner string
}

// GarbledText is the reply to an owner text dropped for conflicting parts.
const GarbledText = "Message garbled, please resend."

// Errors.
var (
	ErrBusy      = errors.New("at: a call is already in progress")
	ErrNumber    = errors.New("at: not a dialable number")
	ErrModel     = errors.New("at: modem model is not qualified for this profile")
	ErrNoAudio   = errors.New("at: call has no audio route")
	ErrCallEnded = errors.New("at: call ended")
)

// Timeouts per command class.
const (
	cmdTimeout  = 5 * time.Second
	smsTimeout  = 60 * time.Second
	dialTimeout = 30 * time.Second
	// concatTTL drops a concatenated text whose parts never all arrive.
	concatTTL = 10 * time.Minute
	// maxConcat bounds texts being reassembled, so forged parts cannot grow
	// memory. ownerConcat of the slots are the owner's number's alone, and
	// no sender keeps more than perSenderConcat pending, so a flood of
	// first parts from strangers cannot push out the owner's long text
	// before its last part arrives (security review 2, finding 7).
	maxConcat       = 32
	ownerConcat     = 4
	perSenderConcat = 4
	// dupTTL is how long a delivered PDU is remembered, so a text the
	// modem hands over twice (a delete that did not happen) is not
	// delivered twice: a replayed code would count as a wrong code.
	dupTTL = 10 * time.Minute
)

// Modem is one modem's SIM.
type Modem struct {
	cfg    Config
	e      *Engine
	number string
	iccid  string

	inbox      chan modem.SMS
	incoming   chan *Call
	smsKick    chan int
	callKick   chan struct{}
	statusKick chan struct{}
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup

	mu      sync.Mutex
	ref     byte
	calls   map[int]*Call
	dialing chan *Call
	parts   map[string]*assembly
	nextSeq uint64
	seen    map[string]time.Time // delivered PDUs, for dupTTL
	garbled time.Time            // last GarbledText sent
	dropped int
	status  Status
}

var _ modem.Modem = (*Modem)(nil)

type assembly struct {
	from     string
	alpha    bool
	owner    bool   // from the owner's number: held in the owner's slots
	seq      uint64 // arrival order, for dropping the oldest
	first    time.Time
	total    int
	parts    map[int]string
	conflict bool
}

// Open initializes the modem on cfg.Port and starts serving it.
func Open(ctx context.Context, cfg Config) (*Modem, error) {
	if cfg.Profile == nil || cfg.Port == nil {
		return nil, errors.New("at: profile and port are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.FramePace == 0 {
		cfg.FramePace = 20 * time.Millisecond
	}
	if cfg.Poll == 0 {
		cfg.Poll = time.Second
	}
	if cfg.Sweep == 0 {
		cfg.Sweep = 30 * time.Second
	}
	urcs := append(append([]string(nil), cfg.Profile.URCs...), cfg.Profile.CallURCs...)
	m := &Modem{
		cfg: cfg, e: NewEngine(cfg.Port, urcs), number: cfg.Number,
		inbox: make(chan modem.SMS, 64), incoming: make(chan *Call, 4),
		smsKick: make(chan int, 64), callKick: make(chan struct{}, 1), statusKick: make(chan struct{}, 1),
		stop: make(chan struct{}), calls: map[int]*Call{}, parts: map[string]*assembly{}, seen: map[string]time.Time{},
	}
	if err := m.init(ctx); err != nil {
		_ = m.e.Close()
		return nil, err
	}
	m.wg.Add(3)
	go m.urcLoop()
	go m.smsLoop()
	go m.callLoop()
	return m, nil
}

func (m *Modem) init(ctx context.Context) error {
	var err error
	for i := 0; i < 3; i++ { // the first AT after power-up may be lost
		if _, err = m.e.Do(ctx, "AT", time.Second); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("at: modem not answering: %w", err)
	}
	do := func(cmd string) error {
		_, err := m.e.Do(ctx, cmd, cmdTimeout)
		return err
	}
	for _, c := range []string{"ATE0", "AT+CMEE=1"} {
		if err := do(c); err != nil {
			return err
		}
	}
	lines, err := m.e.Do(ctx, "AT+CGMM", cmdTimeout)
	if err != nil {
		return err
	}
	if len(lines) == 0 || !m.cfg.Profile.accepts(strings.TrimPrefix(lines[0], "+CGMM: ")) {
		return fmt.Errorf("%w: %q", ErrModel, strings.Join(lines, " "))
	}
	if st := m.readStatus(ctx, simSettle); st.SIM != SIMReady {
		return &SIMError{Status: st}
	}
	m.iccid = m.readICCID(ctx)
	if err := do("AT+CMGF=0"); err != nil {
		return err
	}
	// Texts are kept in the modem's own memory, which is larger than the
	// SIM's; the SIM is the fallback.
	if do(`AT+CPMS="ME","ME","ME"`) != nil {
		if err := do(`AT+CPMS="SM","SM","SM"`); err != nil {
			return err
		}
	}
	cmds := append([]string{"AT+CNMI=2,1,0,0,0", "AT+CLIP=1"}, m.cfg.Profile.Init...)
	if m.cfg.Keys == KeysModem {
		cmds = append(cmds, m.cfg.Profile.KeysOn)
	}
	for _, c := range cmds {
		if err := do(c); err != nil {
			return err
		}
	}
	// Registration notices, so a lost network shows at once. Best effort.
	_ = do("AT+CEREG=1")
	_ = do("AT+CREG=1")
	if c := m.cfg.Profile.NetTimeOn; c != "" {
		_ = do(c) // TIM-1 cross-check only
	}
	m.readStatus(ctx, 0)
	if m.number == "" {
		if lines, err := m.e.Do(ctx, "AT+CNUM", cmdTimeout); err == nil {
			for _, l := range lines {
				if f := fields(strings.TrimPrefix(l, "+CNUM:")); len(f) >= 2 && f[1] != "" {
					m.number = E164(f[1], 0, m.cfg.CountryCode)
					break
				}
			}
		}
	}
	return nil
}

// Number is the SIM's own number ("" when unknown).
func (m *Modem) Number() string { return m.number }

// Inbox delivers texts received by the SIM, reassembled.
func (m *Modem) Inbox() <-chan modem.SMS { return m.inbox }

// Calls delivers incoming calls while they ring. The caller decides whether
// to answer; a call not answered keeps ringing until the far end gives up.
func (m *Modem) Calls() <-chan *Call { return m.incoming }

// Done is closed when the modem has gone away or been closed.
func (m *Modem) Done() <-chan struct{} { return m.e.Done() }

// Dropped counts received texts that could not be decoded or reassembled.
func (m *Modem) Dropped() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}

// Close stops serving and closes the port.
func (m *Modem) Close() error {
	m.stopOnce.Do(func() { close(m.stop) })
	err := m.e.Close()
	m.wg.Wait()
	return err
}

// Send texts to a number from the SIM, in as many parts as the text needs.
func (m *Modem) Send(to, text string) error {
	m.mu.Lock()
	m.ref++
	ref := m.ref
	m.mu.Unlock()
	subs, err := EncodeSubmit(to, text, ref)
	if err != nil {
		return err
	}
	for _, s := range subs {
		_, err := m.e.DoPrompt(context.Background(), "AT+CMGS="+strconv.Itoa(s.Len), s.Hex, smsTimeout)
		if err != nil {
			if errors.Is(err, modem.ErrDown) {
				return modem.ErrDown
			}
			return fmt.Errorf("at: send: %w", err)
		}
	}
	return nil
}

func (m *Modem) urcLoop() {
	defer m.wg.Done()
	defer m.stopOnce.Do(func() { close(m.stop) })
	for l := range m.e.URCs() {
		switch {
		case strings.HasPrefix(l, "+CMTI:"):
			f := fields(strings.TrimPrefix(l, "+CMTI:"))
			if len(f) == 2 {
				if i, err := strconv.Atoi(f[1]); err == nil {
					select {
					case m.smsKick <- i:
					default: // the sweep finds it
					}
				}
			}
		case strings.HasPrefix(l, "+CPIN:"), strings.HasPrefix(l, "+CEREG:"), strings.HasPrefix(l, "+CREG:"),
			strings.HasPrefix(l, "+SIMCARD:"):
			select {
			case m.statusKick <- struct{}{}:
			default:
			}
		case m.isKey(l):
			if k, ok := m.cfg.Profile.Key(l); ok && m.cfg.Keys == KeysModem {
				if c := m.activeCall(); c != nil {
					c.key(k)
				}
			}
		default:
			m.kickCalls()
		}
	}
}

func (m *Modem) isKey(l string) bool {
	if m.cfg.Profile.Key == nil {
		return false
	}
	_, ok := m.cfg.Profile.Key(l)
	return ok
}

func (m *Modem) kickCalls() {
	select {
	case m.callKick <- struct{}{}:
	default:
	}
}

// ---- texts ----

var cmglRe = regexp.MustCompile(`^\+CMG[LR]:\s*(\d+)?`)

func (m *Modem) smsLoop() {
	defer m.wg.Done()
	ctx := context.Background()
	t := time.NewTicker(m.cfg.Sweep)
	defer t.Stop()
	m.sweep(ctx)
	for {
		select {
		case <-m.stop:
			return
		case i := <-m.smsKick:
			lines, err := m.e.Do(ctx, "AT+CMGR="+strconv.Itoa(i), cmdTimeout)
			if err != nil {
				continue
			}
			for j := 0; j+1 < len(lines); j++ {
				if strings.HasPrefix(lines[j], "+CMGR:") {
					m.receive(ctx, i, lines[j], lines[j+1])
					break
				}
			}
		case <-m.statusKick:
			m.readStatus(ctx, 0)
		case <-t.C:
			m.sweep(ctx)
			m.readStatus(ctx, 0)
		}
	}
}

// sweep reads every stored text: those that arrived while the broker was
// down, and any whose +CMTI was lost.
func (m *Modem) sweep(ctx context.Context) {
	lines, err := m.e.Do(ctx, "AT+CMGL=4", cmdTimeout)
	if err != nil {
		return
	}
	for j := 0; j+1 < len(lines); j++ {
		mt := cmglRe.FindStringSubmatch(lines[j])
		if mt == nil || !strings.HasPrefix(lines[j], "+CMGL:") {
			continue
		}
		i, err := strconv.Atoi(mt[1])
		if err != nil {
			continue
		}
		m.receive(ctx, i, lines[j], lines[j+1])
		j++
	}
	m.expireParts()
}

// receive decodes one stored text, deletes it from the modem, and delivers
// it once whole. Deleting first means a crash loses a text rather than
// replaying it: a replayed approval code would count as a wrong code. A
// line that is not the PDU its header announced (a stray boot line, a
// URC) is left stored for the next sweep.
func (m *Modem) receive(ctx context.Context, idx int, header, pdu string) {
	hf := fields(header[strings.IndexByte(header, ':')+1:])
	want, err := strconv.Atoi(hf[len(hf)-1])
	if got, ok := TPDULen(pdu); err != nil || !ok || got != want {
		return
	}
	d, err := DecodeDeliver(pdu)
	if _, derr := m.e.Do(ctx, "AT+CMGD="+strconv.Itoa(idx), cmdTimeout); derr != nil && !errors.Is(derr, modem.ErrDown) {
		// Left stored; the next sweep tries again.
		return
	}
	now := m.cfg.Now()
	m.mu.Lock()
	for k, at := range m.seen {
		if now.Sub(at) > dupTTL {
			delete(m.seen, k)
		}
	}
	key := strings.ToUpper(strings.TrimSpace(pdu))
	_, dup := m.seen[key]
	m.seen[key] = now
	if err != nil || d.Silent() || dup {
		if !dup {
			m.dropped++
		}
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	alpha := d.TON == 5
	if alpha {
		// A sender ID can spell any number; it never reads as one.
		d.Addr = "alpha:" + d.Addr
	} else {
		d.Addr = E164(d.Addr, d.TON, m.cfg.CountryCode)
	}
	fromOwner := !alpha && m.cfg.Owner != "" && SameNumber(d.Addr, m.cfg.Owner, m.cfg.CountryCode)
	text, ok, conflict := m.assemble(d, fromOwner)
	if conflict && fromOwner {
		m.mu.Lock()
		due := m.garbled.IsZero() || now.Sub(m.garbled) >= time.Hour
		if due {
			m.garbled = now
		}
		m.mu.Unlock()
		if due {
			_ = m.Send(m.cfg.Owner, GarbledText)
		}
	}
	if !ok {
		return
	}
	select {
	case m.inbox <- modem.SMS{From: d.Addr, To: m.number, Text: text, At: now, Segments: segments(text), Alphanumeric: alpha}:
	case <-m.stop:
	}
}

func segments(text string) int { n, _ := modem.Segments(text); return n }

// assemble returns a whole text once every part is in; conflict reports a
// text dropped because two parts disagreed. owner is whether d is from the
// owner's number, whose texts use the owner's slots.
func (m *Modem) assemble(d Deliver, owner bool) (text string, ok, conflict bool) {
	if d.Concat == nil || d.Concat.Total == 1 {
		return d.Text, true, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%d/%d", d.Addr, d.Concat.Ref, d.Concat.Total)
	a := m.parts[key]
	if a == nil {
		// Make room within the sender's own cap, then within its class's
		// slots: the owner's, or the strangers' shared rest. Only texts
		// of the same sender, or of the same class, are ever dropped.
		if m.countLocked(func(x *assembly) bool { return x.from == d.Addr }) >= perSenderConcat {
			m.dropOldestLocked(func(x *assembly) bool { return x.from == d.Addr })
		}
		slots := maxConcat - ownerConcat
		if owner {
			slots = ownerConcat
		}
		if m.countLocked(func(x *assembly) bool { return x.owner == owner }) >= slots {
			m.dropOldestLocked(func(x *assembly) bool { return x.owner == owner })
		}
		m.nextSeq++
		a = &assembly{from: d.Addr, owner: owner, seq: m.nextSeq, first: m.cfg.Now(), total: d.Concat.Total, parts: map[int]string{}}
		m.parts[key] = a
	}
	if prev, dup := a.parts[d.Concat.Seq]; !dup {
		a.parts[d.Concat.Seq] = d.Text
	} else if prev != d.Text {
		// Two different bodies for one part: someone guessed the reference
		// and is trying to replace a segment. Drop the whole text.
		a.conflict = true
	}
	if len(a.parts) < a.total {
		return "", false, false
	}
	delete(m.parts, key)
	if a.conflict {
		m.dropped++
		return "", false, true
	}
	var sb strings.Builder
	for i := 1; i <= a.total; i++ {
		sb.WriteString(a.parts[i])
	}
	return sb.String(), true, false
}

func (m *Modem) countLocked(match func(*assembly) bool) int {
	n := 0
	for _, a := range m.parts {
		if match(a) {
			n++
		}
	}
	return n
}

// dropOldestLocked drops the earliest-started text that match accepts.
func (m *Modem) dropOldestLocked(match func(*assembly) bool) {
	oldest := ""
	for k, a := range m.parts {
		if match(a) && (oldest == "" || a.seq < m.parts[oldest].seq) {
			oldest = k
		}
	}
	if oldest != "" {
		delete(m.parts, oldest)
		m.dropped++
	}
}

// expireParts drops texts whose parts have not all arrived within concatTTL.
// A partial text is never delivered: missing words can change its meaning.
func (m *Modem) expireParts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Now()
	for k, a := range m.parts {
		if now.Sub(a.first) > concatTTL {
			delete(m.parts, k)
			m.dropped++
		}
	}
}

// ---- calls ----

// CallState is a call's state.
type CallState int

const (
	Dialing CallState = iota + 1
	Alerting
	Ringing
	Active
	Ended
)

// Call is one voice call.
type Call struct {
	m        *Modem
	id       int
	incoming bool
	number   string

	mu       sync.Mutex
	state    CallState
	active   chan struct{}
	ended    chan struct{}
	audio    chan struct{} // closed once audio is open or has failed
	audioErr error
	stream   Stream
	speech   chan []byte
	keys     chan byte
	chClosed bool
	pumpDone chan struct{}
	sayMu    sync.Mutex
}

// Number is the far end's number ("" when withheld).
func (c *Call) Number() string { return c.number }

// Incoming reports whether the far end called the box.
func (c *Call) Incoming() bool { return c.incoming }

// State is the call's current state.
func (c *Call) State() CallState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Active is closed when the call connects.
func (c *Call) Active() <-chan struct{} { return c.active }

// Ended is closed when the call is over.
func (c *Call) Ended() <-chan struct{} { return c.ended }

// Speech delivers the far end's voice in FrameBytes frames with keypad
// tones muted. This is the only audio the speech service may receive. It is
// closed when the call ends.
func (c *Call) Speech() <-chan []byte { return c.speech }

// Keys delivers keypad presses, decoded by the broker. They never reach
// Speech. It is closed when the call ends.
func (c *Call) Keys() <-chan byte { return c.keys }

// Answer picks up a ringing incoming call.
func (c *Call) Answer(ctx context.Context) error {
	if !c.incoming {
		return errors.New("at: not an incoming call")
	}
	_, err := c.m.e.Do(ctx, "ATA", dialTimeout)
	c.m.kickCalls()
	return err
}

// Hangup ends the call.
func (c *Call) Hangup(ctx context.Context) error {
	_, err := c.m.e.Do(ctx, "AT+CHUP", cmdTimeout)
	if err != nil && !errors.Is(err, modem.ErrDown) {
		_, err = c.m.e.Do(ctx, "ATH", cmdTimeout)
	}
	c.m.kickCalls()
	return err
}

// Say plays pcm (8 kHz S16_LE mono) to the far end at real-time pace and
// returns when it has been written. It waits for the call to connect.
func (c *Call) Say(ctx context.Context, pcm []byte) error {
	select {
	case <-c.audio:
	case <-c.ended:
		return ErrCallEnded
	case <-ctx.Done():
		return ctx.Err()
	}
	if c.audioErr != nil {
		return c.audioErr
	}
	c.sayMu.Lock()
	defer c.sayMu.Unlock()
	t := time.NewTicker(c.m.cfg.FramePace)
	defer t.Stop()
	prev := make([]byte, FrameBytes)
	for i := 0; i < len(pcm); i += FrameBytes {
		f := append([]byte(nil), pcm[i:min(i+FrameBytes, len(pcm))]...)
		if len(f) < FrameBytes {
			f = append(f, make([]byte, FrameBytes-len(f))...)
		}
		// Downlink audio comes from the speech service, which is untrusted:
		// it must not be able to play keypad tones into the call (to an IVR
		// or the owner's voicemail) under the box's name.
		if HasTone(append(append([]byte(nil), prev...), f...)) {
			prev = f
			f = make([]byte, FrameBytes)
		} else {
			prev = f
		}
		if _, err := c.stream.Write(f); err != nil {
			return ErrCallEnded
		}
		select {
		case <-t.C:
		case <-c.ended:
			return ErrCallEnded
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *Call) key(k byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.chClosed {
		return
	}
	select {
	case c.keys <- k:
	default: // a reader 64 keys behind loses keys, never blocks the modem
	}
}

func (c *Call) setState(s CallState) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == s || c.state == Ended {
		return false
	}
	c.state = s
	if s == Active {
		close(c.active)
	}
	return true
}

// Dial calls number from the SIM. It returns once the modem reports the
// call; wait on Active for the far end to answer.
func (m *Modem) Dial(ctx context.Context, number string) (*Call, error) {
	if !dialable(number) {
		return nil, ErrNumber
	}
	w := make(chan *Call, 1)
	m.mu.Lock()
	if len(m.calls) > 0 || m.dialing != nil {
		m.mu.Unlock()
		return nil, ErrBusy
	}
	m.dialing = w
	m.mu.Unlock()
	clear := func() {
		m.mu.Lock()
		if m.dialing == w {
			m.dialing = nil
		}
		m.mu.Unlock()
	}
	if _, err := m.e.Do(ctx, "ATD"+number+";", dialTimeout); err != nil {
		clear()
		return nil, err
	}
	m.kickCalls()
	t := time.NewTimer(dialTimeout)
	defer t.Stop()
	select {
	case c := <-w:
		return c, nil
	case <-t.C:
	case <-ctx.Done():
	}
	clear()
	_, _ = m.e.Do(context.Background(), "AT+CHUP", cmdTimeout)
	return nil, ErrTimeout
}

// dialable accepts an optional + and 3 to 20 digits: nothing else may reach
// an ATD command line.
func dialable(n string) bool {
	d := strings.TrimPrefix(n, "+")
	if len(d) < 3 || len(d) > 20 {
		return false
	}
	for _, c := range d {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (m *Modem) activeCall() *Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.calls {
		if c.State() == Active {
			return c
		}
	}
	return nil
}

func (m *Modem) callLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.cfg.Poll)
	defer t.Stop()
	defer m.endAll()
	for {
		select {
		case <-m.stop:
			return
		case <-m.callKick:
		case <-t.C:
			m.mu.Lock()
			idle := len(m.calls) == 0 && m.dialing == nil
			m.mu.Unlock()
			if idle {
				continue
			}
		}
		m.reconcile()
	}
}

type clcc struct {
	id       int
	incoming bool
	stat     int
	number   string
}

// parseCLCC reads "+CLCC: <id>,<dir>,<stat>,<mode>,<mpty>[,<number>,<type>...]"
// and keeps voice calls (mode 0).
func parseCLCC(lines []string) []clcc {
	var out []clcc
	for _, l := range lines {
		if !strings.HasPrefix(l, "+CLCC:") {
			continue
		}
		f := fields(strings.TrimPrefix(l, "+CLCC:"))
		if len(f) < 5 || f[3] != "0" {
			continue
		}
		id, err1 := strconv.Atoi(f[0])
		stat, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		c := clcc{id: id, incoming: f[1] == "1", stat: stat}
		if len(f) >= 6 {
			c.number = f[5]
		}
		if len(f) >= 7 && f[6] == "145" && c.number != "" {
			c.number = "+" + strings.TrimPrefix(c.number, "+")
		}
		out = append(out, c)
	}
	return out
}

func (m *Modem) reconcile() {
	lines, err := m.e.Do(context.Background(), "AT+CLCC", cmdTimeout)
	if err != nil {
		if errors.Is(err, modem.ErrDown) {
			m.endAll()
		}
		return
	}
	seen := map[int]bool{}
	var activate []*Call
	for _, e := range parseCLCC(lines) {
		var st CallState
		switch e.stat {
		case 0:
			st = Active
		case 2:
			st = Dialing
		case 3:
			st = Alerting
		case 4:
			st = Ringing
		default:
			// Held calls and waiting calls: the box runs one call at a time.
			continue
		}
		seen[e.id] = true
		m.mu.Lock()
		c := m.calls[e.id]
		if c == nil {
			num := e.number
			if num != "" {
				num = E164(num, 0, m.cfg.CountryCode)
			}
			c = &Call{m: m, id: e.id, incoming: e.incoming, number: num,
				active: make(chan struct{}), ended: make(chan struct{}), audio: make(chan struct{}),
				speech: make(chan []byte, 50), keys: make(chan byte, 64), pumpDone: make(chan struct{})}
			m.calls[e.id] = c
			if !e.incoming && m.dialing != nil {
				m.dialing <- c
				m.dialing = nil
			}
		}
		m.mu.Unlock()
		if c.setState(st) {
			switch st {
			case Ringing:
				select {
				case m.incoming <- c:
				default:
				}
			case Active:
				activate = append(activate, c)
			}
		}
	}
	m.mu.Lock()
	var gone []*Call
	for id, c := range m.calls {
		if !seen[id] {
			gone = append(gone, c)
			delete(m.calls, id)
		}
	}
	m.mu.Unlock()
	sort.Slice(gone, func(i, j int) bool { return gone[i].id < gone[j].id })
	for _, c := range gone {
		m.finish(c)
	}
	for _, c := range activate {
		m.startAudio(c)
	}
}

func (m *Modem) startAudio(c *Call) {
	ctx := context.Background()
	fail := func(err error) {
		c.audioErr = err // written before close(c.audio), read after it
		close(c.audio)
		close(c.pumpDone)
	}
	if m.cfg.Audio == nil {
		fail(ErrNoAudio)
		return
	}
	for _, cmd := range m.cfg.Profile.AudioOn {
		if _, err := m.e.Do(ctx, cmd, cmdTimeout); err != nil {
			fail(fmt.Errorf("%w: %v", ErrNoAudio, err))
			return
		}
	}
	s, err := m.cfg.Audio(ctx)
	if err != nil {
		fail(fmt.Errorf("%w: %v", ErrNoAudio, err))
		return
	}
	c.stream = s
	close(c.audio)
	go c.pump(m.cfg.Keys == KeysInBand)
}

// pump reads uplink audio through the DTMF gate.
func (c *Call) pump(inBand bool) {
	defer close(c.pumpDone)
	g := NewGate()
	buf := make([]byte, FrameBytes)
	for {
		if _, err := io.ReadFull(c.stream, buf); err != nil {
			return
		}
		out, keys := g.Push(buf)
		if inBand {
			for _, k := range keys {
				c.key(k)
			}
		}
		if out == nil {
			continue
		}
		c.mu.Lock()
		if !c.chClosed {
			select {
			case c.speech <- out:
			default: // a slow speech reader loses audio, never the keys
			}
		}
		c.mu.Unlock()
	}
}

func (m *Modem) finish(c *Call) {
	c.mu.Lock()
	if c.state == Ended {
		c.mu.Unlock()
		return
	}
	wasActive := c.state == Active
	c.state = Ended
	close(c.ended)
	c.mu.Unlock()
	if wasActive {
		select {
		case <-c.audio:
		default:
			c.audioErr = ErrCallEnded
			close(c.audio)
		}
		if c.stream != nil {
			for _, cmd := range m.cfg.Profile.AudioOff {
				_, _ = m.e.Do(context.Background(), cmd, cmdTimeout)
			}
			_ = c.stream.Close()
			<-c.pumpDone
		}
	}
	c.mu.Lock()
	c.chClosed = true
	close(c.speech)
	close(c.keys)
	c.mu.Unlock()
}

func (m *Modem) endAll() {
	m.mu.Lock()
	var all []*Call
	for id, c := range m.calls {
		all = append(all, c)
		delete(m.calls, id)
	}
	m.mu.Unlock()
	for _, c := range all {
		m.finish(c)
	}
}

// EnsureUAC sets the Quectel UAC flag in the module's USB composition so
// call audio appears as a sound card. The setting persists in the modem;
// when it changes, the modem restarts and must be opened again.
func (m *Modem) EnsureUAC(ctx context.Context) (changed bool, err error) {
	if m.cfg.Profile != Quectel {
		return false, nil
	}
	lines, err := m.e.Do(ctx, `AT+QCFG="usbcfg"`, cmdTimeout)
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		f := fields(strings.TrimPrefix(l, "+QCFG:"))
		if len(f) < 10 || f[0] != "usbcfg" {
			continue
		}
		if f[9] == "1" {
			return false, nil
		}
		f[9] = "1"
		if _, err := m.e.Do(ctx, `AT+QCFG="usbcfg",`+strings.Join(f[1:], ","), cmdTimeout); err != nil {
			return false, err
		}
		_, _ = m.e.Do(ctx, "AT+CFUN=1,1", cmdTimeout)
		return true, nil
	}
	return false, fmt.Errorf("at: unreadable usbcfg: %q", strings.Join(lines, " "))
}

// fields splits an AT parameter list on commas outside quotes and unquotes
// each field.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	q := false
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '"':
			q = !q
		case r == ',' && !q:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}
