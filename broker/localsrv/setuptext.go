package localsrv

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// SetupLine is the owner line as setup uses it (P2-2w c4c; §8.1 pairing,
// CH-1, CH-12): whether it can text, the box's number, a text out and the
// next PAIR text in (modemlink.SetupLine).
type SetupLine interface {
	Ready() bool
	Number() string
	Send(ctx context.Context, to, text string) error
	Next(ctx context.Context) (from, text string, ok bool)
}

// SetupTextsPerMinute bounds setup's texts in a minute, beside
// localapi.SetupTextsPerHour.
const SetupTextsPerMinute = 5

var errNotSent = sockets.Code(localapi.ErrNotSent)

func (s *Setup) line(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	if err := decode(args, &struct{}{}); err != nil {
		return nil, err
	}
	if s.cfg.Line == nil || !s.cfg.Line.Ready() {
		return localapi.SetupLine{}, nil
	}
	n := s.cfg.Line.Number()
	if !phoneRe.MatchString(n) {
		n = ""
	}
	return localapi.SetupLine{Ready: true, Number: n}, nil
}

// send texts one of setup's fixed texts (localapi.SetupText), so the page
// cannot have the box's SIM send anything else, within the caps.
func (s *Setup) send(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.SetupSend
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if !phoneRe.MatchString(a.To) || !localapi.SetupText(a.Text) {
		return nil, errBadArgs
	}
	if s.cfg.Line == nil {
		return nil, errNotSent
	}
	if !s.allowText() {
		return nil, errLimited
	}
	ctx, cancel := context.WithTimeout(ctx, localapi.SetupSendWait)
	defer cancel()
	if s.cfg.Line.Send(ctx, a.To, a.Text) != nil {
		return nil, errNotSent
	}
	return struct{}{}, nil
}

// allowText counts one text unless SetupTextsPerMinute went in the last
// minute or localapi.SetupTextsPerHour in the last hour.
func (s *Setup) allowText() bool {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept, minute := s.texts[:0], 0
	for _, t := range s.texts {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
			if now.Sub(t) < time.Minute {
				minute++
			}
		}
	}
	s.texts = kept
	if len(kept) >= localapi.SetupTextsPerHour || minute >= SetupTextsPerMinute {
		return false
	}
	s.texts = append(kept, now)
	return true
}

// inbound answers the next PAIR text, or nothing within
// localapi.SetupInboundWait.
func (s *Setup) inbound(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	if err := decode(args, &struct{}{}); err != nil {
		return nil, err
	}
	if s.cfg.Line == nil {
		return localapi.SetupInbound{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, localapi.SetupInboundWait)
	defer cancel()
	from, text, ok := s.cfg.Line.Next(ctx)
	if !ok {
		return localapi.SetupInbound{}, nil
	}
	return localapi.SetupInbound{From: from, Text: text}, nil
}
