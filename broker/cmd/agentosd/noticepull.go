package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/notice"
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
	maxGet time.Duration // longest one poll may take; the vault's wait is 25s

	boot   string
	after  uint64
	missed uint64
}

func newNoticePuller(socket string, inform func(string) error) *noticePuller {
	return &noticePuller{socket: socket, inform: inform, retry: 5 * time.Second, maxGet: 40 * time.Second}
}

func (p *noticePuller) client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", p.socket)
		},
		DisableKeepAlives: true,
	}}
}

// poll asks once and texts what came back. A notice whose text fails to
// send is not passed over: the next poll asks for it again.
func (p *noticePuller) poll(ctx context.Context, c *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, p.maxGet)
	defer cancel()
	q := url.Values{"boot": {p.boot}, "after": {fmt.Sprint(p.after)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://notice/notices?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notice socket: %s", resp.Status)
	}
	var b notice.Batch
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<16)).Decode(&b); err != nil {
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
	c := p.client()
	for ctx.Err() == nil {
		if err := p.poll(ctx, c); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(p.retry):
			}
		}
	}
}
