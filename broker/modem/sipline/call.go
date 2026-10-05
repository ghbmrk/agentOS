package sipline

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"

	"github.com/ghbmrk/agentos/broker/modem/secondline"
)

// frameSamples is one 20 ms frame at 8 kHz.
const frameSamples = 160

// call is one outbound call. Only one runs at a time.
type call struct {
	l      *Line
	dlg    *sipgo.DialogClientSession
	conn   *net.UDPConn
	ctx    context.Context // ends the INVITE; cancelling it before an answer sends CANCEL
	cancel context.CancelFunc
	active chan struct{}
	ended  chan struct{}
	endMu  sync.Once

	say  sync.Mutex // serializes Say and owns seq and ts
	seq  uint16
	ts   uint32
	sent bool // a frame has been sent (the first carries the marker bit)

	mu  sync.Mutex // guards the fields below
	id  string     // dialog ID once answered
	ans answer
	tx  *srtp.Context
	ss  uint32
	err error
}

var _ secondline.Call = (*call)(nil)

// Dial calls a number. It returns once the INVITE is sent; Active is
// closed when the call is answered with SRTP, Ended when it ends or fails.
func (l *Line) Dial(ctx context.Context, number string) (secondline.Call, error) {
	select {
	case <-l.done:
		return nil, ErrClosed
	default:
	}
	uri, err := l.numberURI(number)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.call != nil {
		select {
		case <-l.call.ended:
		default:
			return nil, ErrBusy
		}
	}
	ip := l.cfg.MediaIP
	if ip == nil {
		ip = net.ParseIP(l.contact.Address.Host)
	}
	if ip == nil {
		return nil, errors.New("sipline: no address for call audio; set MediaIP")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, err
	}
	off, err := newOffer(ip, conn.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req := l.request(sip.INVITE, uri, uri)
	contact := l.contact
	req.AppendHeader(&contact)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody([]byte(off.String()))

	cctx, cancel := context.WithCancel(context.Background())
	c := &call{l: l, conn: conn, ctx: cctx, cancel: cancel, active: make(chan struct{}), ended: make(chan struct{})}
	var b [10]byte
	_, _ = rand.Read(b[:])
	c.ss = binary.BigEndian.Uint32(b[:])
	c.seq = binary.BigEndian.Uint16(b[4:]) // RFC 3550: random first sequence number and timestamp
	c.ts = binary.BigEndian.Uint32(b[6:])
	ua := &sipgo.DialogUA{Client: l.cli, ContactHDR: contact, RewriteContact: true}
	if c.dlg, err = ua.WriteInvite(ctx, req); err != nil {
		cancel()
		_ = conn.Close()
		return nil, err
	}
	l.call = c
	go c.run(off)
	return c, nil
}

func (c *call) run(off offer) {
	d := c.dlg
	for attempt := 0; ; attempt++ {
		err := d.WaitAnswer(c.ctx, sipgo.AnswerOptions{})
		var de *sipgo.ErrDialogResponse
		if errors.As(err, &de) && attempt == 0 &&
			(de.Res.StatusCode == sip.StatusUnauthorized || de.Res.StatusCode == sip.StatusProxyAuthRequired) {
			if err = c.l.authorize(c.ctx, d.InviteRequest, de.Res); err == nil {
				d.InviteRequest.CSeq().SeqNo++
				d.InviteRequest.RemoveHeader("Via")
				err = d.Invite(c.ctx)
			}
			if err == nil {
				continue
			}
		}
		if err != nil {
			c.end(err)
			return
		}
		break
	}
	ackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Ack(ackCtx); err != nil {
		c.end(err)
		return
	}
	c.l.mu.Lock()
	p := c.l.provider
	c.l.mu.Unlock()
	ans, err := parseAnswer(d.InviteResponse.Body(), p != nil && (p.IsLoopback() || p.IsPrivate()))
	var tx *srtp.Context
	if err == nil {
		tx, err = Context(off.key)
	}
	if err != nil {
		// Answered without SRTP (or unusably): hang up before a word.
		if bye := d.Bye(ackCtx); bye != nil {
			err = errors.Join(err, fmt.Errorf("sipline: hanging up: %w", bye))
		}
		c.end(err)
		return
	}
	c.mu.Lock()
	c.id, c.ans, c.tx = d.ID, ans, tx
	c.mu.Unlock()
	close(c.active)
	go c.drain()
	select {
	case <-d.Context().Done():
		c.end(nil)
	case <-c.ended:
	}
}

// drain reads and drops the far end's audio, so it never backs up; the
// line only speaks (speech recognition is a later package, at M13).
func (c *call) drain() {
	buf := make([]byte, 1500)
	for {
		if _, _, err := c.conn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func (c *call) end(err error) {
	c.endMu.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		c.cancel()
		_ = c.conn.Close()
		close(c.ended)
	})
}

func (c *call) Active() <-chan struct{} { return c.active }
func (c *call) Ended() <-chan struct{}  { return c.ended }

// ID is the call's dialog ID once answered.
func (c *call) ID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

// Err is why the call ended, nil for an ordinary hangup.
func (c *call) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Say plays 8 kHz 16-bit little-endian mono audio, paced in 20 ms frames.
// It returns once the last frame is sent.
func (c *call) Say(ctx context.Context, pcm []byte) error {
	select {
	case <-c.active:
	default:
		return errors.New("sipline: call not answered")
	}
	c.say.Lock()
	defer c.say.Unlock()
	c.mu.Lock()
	ans, srtpTx := c.ans, c.tx
	c.mu.Unlock()
	encode := ULaw
	if ans.pt == PCMA {
		encode = ALaw
	}
	payload := encode(pcm)
	silence := encode([]byte{0, 0})[0]
	tick := time.NewTicker(c.l.cfg.FramePace)
	defer tick.Stop()
	for i := 0; i < len(payload); i += frameSamples {
		frame := make([]byte, frameSamples)
		n := copy(frame, payload[i:])
		for j := n; j < frameSamples; j++ {
			frame[j] = silence
		}
		p := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: uint8(ans.pt), SequenceNumber: c.seq, Timestamp: c.ts, SSRC: c.ss, Marker: !c.sent}, Payload: frame}
		raw, err := p.Marshal()
		if err != nil {
			return err
		}
		sealed, err := srtpTx.EncryptRTP(nil, raw, nil)
		if err != nil {
			return err
		}
		if _, err := c.conn.WriteToUDP(sealed, ans.addr); err != nil {
			return err
		}
		c.seq++
		c.ts += frameSamples
		c.sent = true
		select {
		case <-tick.C:
		case <-c.ended:
			return errors.New("sipline: call ended")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Hangup ends the call: CANCEL while it rings, BYE once answered.
func (c *call) Hangup(ctx context.Context) error {
	select {
	case <-c.ended:
		return nil
	default:
	}
	select {
	case <-c.active:
		err := c.dlg.Bye(ctx)
		c.end(nil)
		return err
	default:
		c.cancel() // WaitAnswer sends CANCEL
		select {
		case <-c.ended:
		case <-ctx.Done():
			c.end(nil)
		}
		return nil
	}
}
