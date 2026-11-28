package inbox

import (
	"bytes"
	"sync"
	"time"
)

// gReadCacheMax bounds a ReadCache in bytes, as openedMax bounds one Opened
// call: a read mail past it is got again on each Opened. A var for tests.
var gReadCacheMax = OpenedMax

// gReadCost is what a cached mail costs beside its id and header bytes: the
// map slot, the strings' and slice's headers and the time (#3010).
const gReadCost = 128

// ReadCache keeps, for each Gmail message id Opened has read, the header
// lines and arrival Opened takes from its metadata get (#3010). Gmail never
// changes a message's From, Message-ID or internalDate, so a later Opened
// lists the read mail and gets only the ids it lacks. It keeps the ids the
// last full listing named, within gReadCacheMax, so a mail gone from the
// account leaves it at the next Opened that gets through. The header is kept
// as Opened read it, the access token of that time already redacted. It is
// safe for concurrent use; the zero value is not, use NewReadCache.
type ReadCache struct {
	mu    sync.Mutex
	ids   map[string]cachedRead
	spent int
}

// cachedRead is one cached read mail.
type cachedRead struct {
	raw     []byte
	arrived time.Time
}

// NewReadCache is an empty cache, to share across the Gmail boxes of one
// account (WithReadCache).
func NewReadCache() *ReadCache { return &ReadCache{ids: map[string]cachedRead{}} }

// Len is how many mails c holds.
func (c *ReadCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ids)
}

func (c *ReadCache) get(id string) (cachedRead, bool) {
	if c == nil {
		return cachedRead{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.ids[id]
	return r, ok
}

// readPass is one Opened's cache: the mails its listing named, cached or got,
// within the bound, to replace c's at the end.
type readPass struct {
	c     *ReadCache
	ids   map[string]cachedRead
	spent int
}

func (c *ReadCache) pass() *readPass {
	return &readPass{c: c, ids: map[string]cachedRead{}}
}

// keep adds the read mail id to the pass if it fits.
func (p *readPass) keep(id string, r cachedRead) {
	if p.c == nil {
		return
	}
	n := len(id) + len(r.raw) + gReadCost
	if _, ok := p.ids[id]; ok || p.spent+n > gReadCacheMax {
		return
	}
	p.ids[id] = cachedRead{raw: bytes.Clone(r.raw), arrived: r.arrived}
	p.spent += n
}

// end makes the pass the cache once its listing got through (whole), so
// mail gone from the account leaves it; a pass that failed part way only
// adds what fits, so a failing account still caches what it read.
func (p *readPass) end(whole bool) {
	c := p.c
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if whole {
		c.ids, c.spent = p.ids, p.spent
		return
	}
	for id, r := range p.ids {
		n := len(id) + len(r.raw) + gReadCost
		if _, ok := c.ids[id]; ok || c.spent+n > gReadCacheMax {
			continue
		}
		c.ids[id] = r
		c.spent += n
	}
}

// WithReadCache makes g read through c, shared with other boxes over the
// same account, and returns g. Call it before g is used.
func (g *Gmail) WithReadCache(c *ReadCache) *Gmail {
	g.reads = c
	return g
}
