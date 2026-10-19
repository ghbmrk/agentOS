package main

import (
	"context"
	"log"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/notice"
	"github.com/ghbmrk/agentos/broker/owner/notice/noticesock"
)

// noticeMissedText is what the owner reads when the vault process's queue
// overflowed: the notices are gone, so the page is where to look.
const noticeMissedText = "Some notices from my vault process were dropped unread. Sign in to my Wi-Fi page and check your accounts."

// noticePuller long-polls the vault process's notice socket and texts the
// owner each notice through inform, rendered from notice.Text; nothing the
// vault process sends is ever passed on as free text (P2-2w c4e4 s2b, #1421).
type noticePuller struct {
	socket string
	inform func(string) error
	retry  time.Duration // pause after a failed poll or a failed text

	boot   string
	after  uint64
	missed uint64
}

func newNoticePuller(socket string, inform func(string) error) *noticePuller {
	return &noticePuller{socket: socket, inform: inform, retry: 5 * time.Second}
}

// poll asks once and texts what came back. A notice whose text fails to
// send is not passed over: the next poll asks for it again.
func (p *noticePuller) poll(ctx context.Context, c *noticesock.Client) error {
	b, err := c.Get(ctx, p.boot, p.after)
	if err != nil {
		return err
	}
	if b.Boot != p.boot {
		p.boot, p.after, p.missed = b.Boot, 0, 0
	}
	if b.Missed > p.missed {
		if err := p.inform(noticeMissedText); err != nil {
			return err
		}
		p.missed = b.Missed
	}
	if b.Missed == 0 {
		p.missed = 0
	}
	for _, it := range b.Notices {
		if it.Seq <= p.after {
			continue
		}
		if text, ok := notice.Text(it.Notice); ok {
			if err := p.inform(text); err != nil {
				return err
			}
		} else {
			log.Printf("notice socket: dropped a notice with code %q that has no text", it.Code)
		}
		p.after = it.Seq
	}
	return nil
}

// run polls until ctx ends.
func (p *noticePuller) run(ctx context.Context) {
	c := noticesock.New(p.socket)
	for ctx.Err() == nil {
		if err := p.poll(ctx, c); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(p.retry):
			}
		}
	}
}
