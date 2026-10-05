package recall

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

// Segment limits: the active segment rolls over at either. A deletion
// rewrites the segments holding the deleted items, so these bound its cost.
// Variables so tests can make small segments.
var (
	segMaxLines = 2048
	segMaxBytes = int64(8 << 20)
)

// entry is what memory holds of an item: enough to filter, rank and
// cascade. Text, account, ref and the rest are read from the segment.
type entry struct {
	id      string
	seg     uint32
	off     int64
	size    uint32 // line length without the newline
	doc     uint32 // document number in the text indexes
	kind    string
	label   Label
	labelBy string
	seen    time.Time
	derived []string
	facts   []Fact
	vec     []int8
	vnorm   float32
	vecID   string
}

type segInfo struct {
	lines int // complete lines in the file, live or not
	live  int // lines that are an item's current version
	size  int64
}

// diskItem is an item as a segment line: its vector quantized to int8
// (base64 in JSON) rather than float32 text.
type diskItem struct {
	Item
	Q  []byte  `json:"q,omitempty"`
	QS float32 `json:"qs,omitempty"`
}

func encodeItem(it *Item) ([]byte, error) {
	d := diskItem{Item: *it}
	d.Vector = nil
	if len(it.Vector) > 0 {
		q, s := quantize(it.Vector)
		d.Q = make([]byte, len(q))
		for i, x := range q {
			d.Q[i] = byte(x)
		}
		d.QS = s
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func decodeItem(line []byte) (Item, []int8, error) {
	var d diskItem
	if err := json.Unmarshal(line, &d); err != nil {
		return Item{}, nil, err
	}
	if d.ID == "" {
		return Item{}, nil, errors.New("recall: item line without an id")
	}
	var q []int8
	if len(d.Q) > 0 {
		q = make([]int8, len(d.Q))
		for i, x := range d.Q {
			q[i] = int8(x)
		}
		d.Vector = dequantize(q, d.QS)
	}
	return d.Item, q, nil
}

// lineID reads the id at the head of an item line without decoding the
// rest; encoding/json writes Item.ID first.
func lineID(line []byte) string {
	const pre = `{"id":"`
	if bytes.HasPrefix(line, []byte(pre)) {
		rest := line[len(pre):]
		if i := bytes.IndexByte(rest, '"'); i > 0 && bytes.IndexByte(rest[:i], '\\') < 0 {
			return string(rest[:i])
		}
	}
	var d struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(line, &d) != nil {
		return ""
	}
	return d.ID
}

// lineOffsets splits segment content into complete lines with their
// offsets. A final segment without a newline is a torn write.
func lineOffsets(data []byte) (lines [][]byte, offs []int64, torn bool) {
	var off int64
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return lines, offs, true
		}
		lines = append(lines, data[:i])
		offs = append(offs, off)
		data = data[i+1:]
		off += int64(i + 1)
	}
	return lines, offs, false
}

func (ix *Index) seg(n uint32) *segInfo {
	si := ix.segs[n]
	if si == nil {
		si = &segInfo{}
		ix.segs[n] = si
	}
	return si
}

// readItem reads e's current version from its segment. Caller holds mu.
func (ix *Index) readItem(e *entry) (Item, error) {
	buf := make([]byte, e.size)
	if err := ix.dir.ReadAt(e.seg, e.off, buf); err != nil {
		return Item{}, err
	}
	it, _, err := decodeItem(buf)
	if err != nil {
		return Item{}, err
	}
	if it.ID != e.id {
		return Item{}, errors.New("recall: segment does not match the index")
	}
	return it, nil
}

// putLocked writes items (each already admitted) to the active segment,
// one durable append per segment, and indexes them. Caller holds mu.
func (ix *Index) putLocked(items []*Item) error {
	type pend struct {
		it   *Item
		line []byte
	}
	var batch []pend
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		buf := make([]byte, 0, size)
		for _, p := range batch {
			buf = append(buf, p.line...)
		}
		off, err := ix.dir.Append(ix.active, buf)
		if err != nil {
			// A failed append may have left whole or partial lines on disk
			// that memory does not know, so a later deletion would not
			// erase them (CAP-3). Cut the segment back to what memory
			// knows; if that fails too, write elsewhere and keep the
			// segment marked for erase, which blocks tombstone pruning
			// until it succeeds.
			ix.unerased[ix.active] = true
			if rerr := ix.rewriteSeg(ix.active); rerr == nil {
				delete(ix.unerased, ix.active)
			} else {
				ix.active++
			}
			return err
		}
		si := ix.seg(ix.active)
		for _, p := range batch {
			ix.applyPut(p.it, ix.active, off, uint32(len(p.line)-1))
			off += int64(len(p.line))
			si.lines++
			si.size += int64(len(p.line))
		}
		batch, size = nil, 0
		return nil
	}
	for _, it := range items {
		line, err := encodeItem(it)
		if err != nil {
			return err
		}
		si := ix.seg(ix.active)
		pending := si.lines + len(batch)
		if pending > 0 && (pending >= segMaxLines || si.size+int64(size+len(line)) > segMaxBytes) {
			if err := flush(); err != nil {
				return err
			}
			ix.active++
		}
		batch = append(batch, pend{it, line})
		size += len(line)
	}
	if err := flush(); err != nil {
		return err
	}
	return ix.maybeCompactSegs()
}

// applyPut makes it the current version of its ID, stored at (seg, off).
// Caller holds mu.
func (ix *Index) applyPut(it *Item, seg uint32, off int64, size uint32) {
	if old := ix.items[it.ID]; old != nil {
		text := ""
		if prev, err := ix.readItem(old); err == nil {
			text = searchText(&prev)
		}
		ix.dropLocked(old, text, true)
	}
	e := &entry{
		id: it.ID, seg: seg, off: off, size: size, doc: ix.nextDoc,
		kind: intern(it.Source.Kind), label: it.Label, labelBy: it.LabelBy, seen: it.Source.Seen,
		derived: it.Source.DerivedFrom, facts: it.Facts, vecID: intern(it.VecID),
	}
	ix.nextDoc++
	if len(it.Vector) > 0 {
		e.vec, _ = quantize(it.Vector)
		e.vnorm = normQ(e.vec)
	}
	ix.index(e, searchText(it))
	ix.seg(seg).live++
}

// index adds e to memory. Caller holds mu.
func (ix *Index) index(e *entry, text string) {
	ix.items[e.id] = e
	ix.byDoc[e.doc] = e
	ix.all.add(e.doc, text)
	if e.label == Public {
		ix.pub.add(e.doc, text)
	}
	for _, p := range e.derived {
		ix.children[p] = append(ix.children[p], e.id)
	}
}

// dropLocked removes e from memory. text is its search text as indexed;
// if it could not be read, postings for e stay behind and are ignored,
// since byDoc no longer names it. A superseded version is remembered so a
// later deletion erases it too. Caller holds mu.
func (ix *Index) dropLocked(e *entry, text string, superseded bool) {
	if text != "" {
		ix.all.remove(e.doc, text)
		ix.pub.remove(e.doc, text)
	}
	delete(ix.byDoc, e.doc)
	if ix.items[e.id] == e {
		delete(ix.items, e.id)
	}
	for _, p := range e.derived {
		cs := ix.children[p]
		for i, c := range cs {
			if c == e.id {
				cs = append(cs[:i], cs[i+1:]...)
				break
			}
		}
		if len(cs) == 0 {
			delete(ix.children, p)
		} else {
			ix.children[p] = cs
		}
	}
	if si := ix.segs[e.seg]; si != nil {
		si.live--
	}
	ix.dirty[e.seg] = true
	if superseded && !containsSeg(ix.older[e.id], e.seg) {
		ix.older[e.id] = append(ix.older[e.id], e.seg)
	}
}

func containsSeg(ns []uint32, n uint32) bool {
	for _, x := range ns {
		if x == n {
			return true
		}
	}
	return false
}

// maybeCompactSegs rewrites sealed segments that are mostly superseded
// versions. Caller holds mu.
func (ix *Index) maybeCompactSegs() error {
	todo := map[uint32]bool{}
	for n := range ix.dirty {
		delete(ix.dirty, n)
		si := ix.segs[n]
		if si != nil && n != ix.active && si.lines > 64 && 2*si.live < si.lines {
			todo[n] = true
		}
	}
	return ix.rewriteSegs(todo)
}

// rewriteSegs rewrites each segment with only its live lines; a failure is
// remembered and retried. Caller holds mu.
func (ix *Index) rewriteSegs(ns map[uint32]bool) error {
	order := make([]uint32, 0, len(ns))
	for n := range ns {
		order = append(order, n)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	var errs []error
	for _, n := range order {
		if err := ix.rewriteSeg(n); err != nil {
			ix.unerased[n] = true
			errs = append(errs, err)
			continue
		}
		delete(ix.unerased, n)
	}
	return errors.Join(errs...)
}

// rewriteSeg keeps only the lines of segment n that are an item's current
// version. Caller holds mu.
func (ix *Index) rewriteSeg(n uint32) error {
	data, err := ix.dir.ReadSegment(n)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			delete(ix.segs, n)
			return nil
		}
		return err
	}
	lines, offs, _ := lineOffsets(data)
	var out []byte
	type moved struct {
		e   *entry
		off int64
	}
	var keep []moved
	var dropped []string
	for i, l := range lines {
		id := lineID(l)
		if e := ix.items[id]; id != "" && e != nil && e.seg == n && e.off == offs[i] {
			keep = append(keep, moved{e, int64(len(out))})
			out = append(append(out, l...), '\n')
			continue
		}
		if id != "" {
			dropped = append(dropped, id)
		}
	}
	if len(keep) == 0 && n != ix.active {
		err = ix.dir.Rewrite(n, nil)
	} else {
		if out == nil {
			out = []byte{}
		}
		err = ix.dir.Rewrite(n, out)
	}
	if err != nil {
		return err
	}
	for _, m := range keep {
		m.e.off = m.off
	}
	if len(keep) == 0 && n != ix.active {
		delete(ix.segs, n)
	} else {
		ix.segs[n] = &segInfo{lines: len(keep), live: len(keep), size: int64(len(out))}
	}
	for _, id := range dropped {
		ns := ix.older[id]
		for i, x := range ns {
			if x == n {
				ns = append(ns[:i], ns[i+1:]...)
				break
			}
		}
		if len(ns) == 0 {
			delete(ix.older, id)
		} else {
			ix.older[id] = ns
		}
	}
	return nil
}

// loadSegments rebuilds memory from the segments: only each ID's latest
// version not covered by its tombstone is indexed. Segments holding torn,
// unreadable, or deleted content are rewritten without it.
func (ix *Index) loadSegments() error {
	ns, err := ix.dir.Segments()
	if err != nil {
		return err
	}
	type loc struct {
		seg  uint32
		off  int64
		size uint32
	}
	latest := map[string]loc{}
	versions := map[string][]uint32{}
	fix := map[uint32]bool{}
	for _, n := range ns {
		data, err := ix.dir.ReadSegment(n)
		if err != nil {
			return err
		}
		lines, offs, torn := lineOffsets(data)
		if torn {
			fix[n] = true
		}
		si := ix.seg(n)
		si.lines, si.size = len(lines), int64(len(data))
		for i, l := range lines {
			id := lineID(l)
			if id == "" {
				ix.skipped++
				fix[n] = true
				continue
			}
			if t, ok := ix.tombs[id]; ok {
				// Content a deletion covers is never loaded, and is erased.
				it, _, err := decodeItem(l)
				if err != nil || !it.Received.After(t) {
					if err != nil {
						ix.skipped++
					}
					fix[n] = true
					continue
				}
			}
			if prev, ok := latest[id]; ok && !containsSeg(versions[id], prev.seg) {
				versions[id] = append(versions[id], prev.seg)
			}
			latest[id] = loc{n, offs[i], uint32(len(l))}
		}
	}
	if len(ns) > 0 {
		ix.active = ns[len(ns)-1]
	} else {
		ix.active = 1
	}
	// Index in segment order, so document numbers follow storage order.
	byseg := map[uint32][]string{}
	for id, l := range latest {
		byseg[l.seg] = append(byseg[l.seg], id)
	}
	for _, n := range ns {
		ids := byseg[n]
		if len(ids) == 0 {
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return latest[ids[i]].off < latest[ids[j]].off })
		for _, id := range ids {
			l := latest[id]
			buf := make([]byte, l.size)
			if err := ix.dir.ReadAt(n, l.off, buf); err != nil {
				return err
			}
			it, q, err := decodeItem(buf)
			if err != nil || it.ID != id {
				ix.skipped++
				fix[n] = true
				continue
			}
			e := &entry{
				id: id, seg: n, off: l.off, size: l.size, doc: ix.nextDoc,
				kind: intern(it.Source.Kind), label: it.Label, labelBy: it.LabelBy, seen: it.Source.Seen,
				derived: it.Source.DerivedFrom, facts: it.Facts, vecID: intern(it.VecID), vec: q,
			}
			if e.label != Public {
				e.label = Private
			}
			if q != nil {
				e.vnorm = normQ(q)
			}
			ix.nextDoc++
			ix.index(e, searchText(&it))
			ix.segs[n].live++
		}
	}
	ix.all.trim()
	ix.pub.trim()
	for id, vs := range versions {
		if _, ok := ix.items[id]; ok {
			ix.older[id] = vs
		} else {
			// Every version is covered by a tombstone or unreadable.
			for _, n := range vs {
				fix[n] = true
			}
		}
	}
	for n, si := range ix.segs {
		if n != ix.active && si.lines > 64 && 2*si.live < si.lines {
			fix[n] = true
		}
	}
	return ix.rewriteSegs(fix)
}

// loadMeta replays the meta log and reports whether it needs a rewrite.
func (ix *Index) loadMeta() (bool, error) {
	data, err := ix.meta.ReadAll()
	if err != nil {
		return false, err
	}
	lines, torn := Lines(data)
	bad := 0
	for _, l := range lines {
		var r record
		if err := json.Unmarshal(l, &r); err != nil {
			bad++
			continue
		}
		ix.applyMeta(r)
	}
	ix.skipped += bad
	ix.metaLines = len(lines)
	return torn || bad > 0, nil
}

func (ix *Index) applyMeta(r record) {
	switch r.Op {
	case "hdr":
		if r.Header == nil {
			return
		}
		ix.hdrEmb = r.Header.Embedder
		if !ix.keyGiven && r.Header.Key != "" {
			if k, err := hex.DecodeString(r.Header.Key); err == nil && len(k) >= 16 {
				ix.keyer = Keyer{key: k}
			}
		}
	case "pref":
		if r.Pref != nil {
			ix.prefs[r.Pref.Key] = *r.Pref
		}
	case "tomb":
		if r.ID != "" {
			ix.tombs[r.ID] = r.At
		}
	case "used":
		if r.ID != "" {
			ix.used[r.ID] = true
		}
	}
}

// appendMeta makes one meta record durable. Caller holds mu.
func (ix *Index) appendMeta(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := ix.meta.Append(append(b, '\n')); err != nil {
		return err
	}
	ix.metaLines++
	return nil
}

func (ix *Index) maybeCompactMeta() error {
	live := len(ix.prefs) + len(ix.tombs) + len(ix.used) + 1
	if ix.metaLines > 64 && ix.metaLines > 2*live {
		return ix.compactMeta()
	}
	return nil
}

// compactMeta rewrites the meta log with only the live state: header,
// preferences, tombstones and used owner messages. Caller holds mu.
func (ix *Index) compactMeta() error {
	var buf []byte
	n := 0
	put := func(r record) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf = append(append(buf, b...), '\n')
		n++
		return nil
	}
	h := &header{Embedder: ix.embID()}
	if !ix.keyGiven {
		h.Key = hex.EncodeToString(ix.keyer.key)
	}
	if err := put(record{Op: "hdr", Header: h}); err != nil {
		return err
	}
	keys := make([]string, 0, len(ix.prefs))
	for k := range ix.prefs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := ix.prefs[k]
		if err := put(record{Op: "pref", Pref: &p}); err != nil {
			return err
		}
	}
	tids := make([]string, 0, len(ix.tombs))
	for id := range ix.tombs {
		tids = append(tids, id)
	}
	sort.Strings(tids)
	for _, id := range tids {
		if err := put(record{Op: "tomb", ID: id, At: ix.tombs[id]}); err != nil {
			return err
		}
	}
	uids := make([]string, 0, len(ix.used))
	for id := range ix.used {
		uids = append(uids, id)
	}
	sort.Strings(uids)
	for _, id := range uids {
		if err := put(record{Op: "used", ID: id}); err != nil {
			return err
		}
	}
	if err := ix.meta.Rewrite(buf); err != nil {
		return err
	}
	ix.metaLines = n
	ix.hdrEmb = h.Embedder
	return nil
}

// interned holds the few distinct kind and embedder strings once.
var (
	internMu sync.Mutex
	interned = map[string]string{}
)

func intern(s string) string {
	if s == "" {
		return ""
	}
	internMu.Lock()
	defer internMu.Unlock()
	if v, ok := interned[s]; ok {
		return v
	}
	if len(interned) < 256 {
		interned[s] = s
	}
	return s
}
