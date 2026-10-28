package imapsmtp

import (
	"context"
	"slices"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// addrBatch is how many UIDs one of AddrHeads' requests names. Its window is
// a Seen batch's: seenBase, plus headMax and fetchFrame for each UID.
const addrBatch = seenBatch

// AddrHeads hands each the From, To and Cc header fields and the
// INTERNALDATE of every one of uids in folder, read with BODY.PEEK[HEADER.FIELDS
// (FROM TO CC)] so nothing is marked read, only while folder still has the
// UID validity the UIDs were listed under: what the clerk's history, known
// senders and contacts are read from (MAIL-world-b1). The UIDs are fetched
// addrBatch at a time in one session, signed in once, each batch one typed
// request under a fresh window. Every UID must answer with its fields, at
// most headMax bytes: a mail gone since it was listed (ErrUnanswered), a
// folder renumbered since (ErrValidity), a header too long (a
// LongHeaderError naming its folder and arrival), an answer outside the
// request, or an error from each fails the call, so no partial answer passes
// for a full one.
func (s *Store) AddrHeads(ctx context.Context, folder string, validity uint32, uids []uint32, each func(header []byte, arrived time.Time) error) error {
	uids = slices.Compact(slices.Sorted(slices.Values(uids)))
	if len(uids) == 0 {
		return nil
	}
	return s.session(ctx, func(x *session) error {
		for i := 0; i < len(uids); i += addrBatch {
			batch := uids[i:min(i+addrBatch, len(uids))]
			want := set(batch)
			r, err := x.do(imapwire.Request{Op: imapwire.OpAddrHeads, Folder: folder, Validity: validity, UIDs: batch},
				seenBase+addrBatch*(headMax+fetchFrame), read)
			if err != nil && r.Err == "" {
				return err
			}
			// As Seen: each header in turn, then why the batch ended.
			var bad error
			for _, h := range r.Heads {
				if !want[h.UID] || len(h.Header) > headMax {
					return errLied
				}
				delete(want, h.UID)
				if bad == nil {
					bad = each(h.Header, h.Arrived)
				}
			}
			switch {
			case r.Err != "" && r.Err != codeLong:
				return err
			case bad != nil:
				return stand{bad}
			case r.Err == codeLong:
				return x.longHeader(folder, r.Long, want)
			case len(want) > 0:
				return errLied // an answer that said it was whole and was not
			}
		}
		return nil
	})
}
