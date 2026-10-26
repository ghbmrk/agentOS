package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// PageConfig is what agentosd opens the page authority from (OWN-page-https,
// #3153; CH-9, HW-1).
type PageConfig struct {
	// Dir is agentosd's own state directory; Sealer seals the authority's
	// file there. A nil Sealer is no authority (every shipped box until the
	// STO-2 start-up path wires the real one).
	Dir    string
	Sealer pageca.Sealer
	// Name is the page name (pageca.DefaultName when empty); Built is the
	// image's build time, the authority's NotBefore plus a day.
	Name  string
	Built time.Time
	// Claimed: the box has a claim recorded, so a missing authority is
	// never made anew.
	Claimed bool
	Rand    io.Reader
	// Log takes one fixed line; log.Print when nil.
	Log func(string)
}

// Page is the page authority as agentosd holds it: open, absent, or owed a
// restore. Its key never leaves this process.
type Page struct {
	a       *pageca.Authority
	restore bool
	rand    io.Reader
}

// Fixed log lines: never an error's text (it can carry a path).
const (
	LogPageNoSealer = "page authority: no sealer; the owner page serves HTTP only"
	LogPageRestore  = "page authority: missing though I am claimed; the owner page serves HTTP only until I am restored"
	LogPageNotOpen  = "page authority: did not open; the owner page serves HTTP only"
	LogPageOpen     = "page authority: open"
)

// OpenPage opens the page authority, making it only on a fresh box with no
// file (pageca.OpenOrCreate). It never fails: a box without one serves the
// page over HTTP only, and says why once in the log.
func OpenPage(c PageConfig) *Page {
	logf := c.Log
	if logf == nil {
		logf = func(s string) { log.Print(s) }
	}
	if c.Name == "" {
		c.Name = pageca.DefaultName
	}
	if c.Sealer == nil {
		logf(LogPageNoSealer)
		return &Page{}
	}
	a, err := pageca.OpenOrCreate(pageca.Store{Dir: c.Dir, Sealer: c.Sealer}, c.Name, c.Built, c.Claimed, c.Rand)
	switch {
	case errors.Is(err, pageca.ErrRestore):
		logf(LogPageRestore)
		return &Page{restore: true}
	case err != nil:
		logf(LogPageNotOpen)
		return &Page{}
	}
	logf(LogPageOpen)
	return &Page{a: a, rand: c.Rand}
}

var (
	errNoAuthority = sockets.Code(localapi.ErrNoAuthority)
	errRestore     = sockets.Code(localapi.ErrRestore)
)

// certify signs the page's serving key for the page name (OpCertify). It
// returns the leaf and the authority's certificate only.
func (s *Server) certify(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	p := s.cfg.Page
	if p == nil {
		s.noPage.Do(func() { log.Print(LogPageNoSealer) })
		return nil, errNoAuthority
	}
	if p.restore {
		return nil, errRestore
	}
	if p.a == nil {
		return nil, errNoAuthority
	}
	var a localapi.CertifyArgs
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if len(a.Pub) == 0 || len(a.Pub) > localapi.MaxPub {
		return nil, errBadArgs
	}
	leaf, err := p.a.Issue(a.Pub, s.cfg.Now(), p.rand)
	switch {
	case errors.Is(err, pageca.ErrKey):
		return nil, errBadArgs
	case err != nil:
		return nil, errFailed
	}
	return localapi.Certified{Leaf: leaf, Authority: p.a.Certificate()}, nil
}
