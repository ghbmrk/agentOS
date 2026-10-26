package imapsmtp

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// planBatch is how many UIDs one of PlanHeads' requests names, for dates
// and headers alike. Each request's window is fixed by it, as a Seen
// batch's is: seenBase, plus fetchFrame for each date, or headMax and
// fetchFrame for each header.
const planBatch = seenBatch

// planned is one mail PlanHeads may read: where it is and when it arrived.
type planned struct {
	folder   string
	validity uint32
	uid      uint32
	arrived  time.Time
}

// PlanHeads hands each the From and Authentication-Results header fields of
// the newest n mails across every folder but junk and trash, read with
// BODY.PEEK[HEADER.FIELDS (FROM AUTHENTICATION-RESULTS)] so nothing is
// marked read: all setup's account plan reads of a mail over IMAP
// (TN-account-plan, #3220). Newest is by INTERNALDATE, which the server
// sets: it lists the folders, each folder's UIDs, and the INTERNALDATE of
// its n highest, keeps the n newest across folders, and only then fetches
// their headers, so at most n headers are read whatever the folders hold.
// It is one session, signed in once, each request one typed read under a
// fresh window. A mail gone between the listing and the fetch, a folder
// renumbered since (ErrValidity), and a mail whose fields pass headMax are
// skipped, as the Gmail reader skips a mail gone or too large; anything
// else, or an error from each, fails the call, so no partial answer passes
// for a full one.
func (s *Store) PlanHeads(ctx context.Context, n int, each func(header []byte) error) error {
	return s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpFolders}, s.replyBudget(0), read)
		if err != nil {
			return err
		}
		var pick []planned
		for _, f := range r.Folders {
			if f.Name == "" || !f.Role.Known() {
				return errLied
			}
			if f.Role == Junk || f.Role == Trash {
				continue
			}
			u, err := x.do(imapwire.Request{Op: imapwire.OpUIDs, Folder: f.Name}, s.replyBudget(0), read)
			if err != nil {
				return err
			}
			uids := slices.Compact(slices.Sorted(slices.Values(u.UIDs)))
			uids = uids[max(0, len(uids)-n):]
			for i := 0; i < len(uids); i += planBatch {
				batch := uids[i:min(i+planBatch, len(uids))]
				d, err := x.do(imapwire.Request{Op: imapwire.OpDates, Folder: f.Name, Validity: u.Validity, UIDs: batch},
					seenBase+planBatch*fetchFrame, read)
				if errors.Is(err, ErrValidity) {
					break // renumbered since it was listed: its mails are gone
				}
				if err != nil {
					return err
				}
				want := set(batch)
				for _, h := range d.Heads {
					if !want[h.UID] || len(h.Header) > 0 {
						return errLied
					}
					delete(want, h.UID)
					pick = append(pick, planned{f.Name, u.Validity, h.UID, h.Arrived})
				}
			}
			pick = newestPlanned(pick, n)
		}
		// By folder, so each request names one folder's UIDs.
		slices.SortFunc(pick, func(a, b planned) int { return cmp.Or(cmp.Compare(a.folder, b.folder), cmp.Compare(a.uid, b.uid)) })
		for len(pick) > 0 {
			k := 0
			for k < len(pick) && k < planBatch && pick[k].folder == pick[0].folder {
				k++
			}
			batch, at := pick[:k], pick[0]
			pick = pick[k:]
			uids := make([]uint32, len(batch))
			for i, p := range batch {
				uids[i] = p.uid
			}
			h, err := x.do(imapwire.Request{Op: imapwire.OpPlanHeads, Folder: at.folder, Validity: at.validity, UIDs: uids},
				seenBase+planBatch*(headMax+fetchFrame), read)
			if errors.Is(err, ErrValidity) {
				continue
			}
			if err != nil {
				return err
			}
			want := set(uids)
			for _, hd := range h.Heads {
				if !want[hd.UID] || len(hd.Header) > headMax {
					return errLied
				}
				delete(want, hd.UID)
				if err := each(hd.Header); err != nil {
					return stand{err}
				}
			}
		}
		return nil
	})
}

// newestPlanned is the n newest of ps by arrival, ties broken by folder and
// UID so the choice does not depend on the order folders were listed in.
func newestPlanned(ps []planned, n int) []planned {
	slices.SortFunc(ps, func(a, b planned) int {
		return cmp.Or(b.arrived.Compare(a.arrived), cmp.Compare(a.folder, b.folder), cmp.Compare(b.uid, a.uid))
	})
	return ps[:min(len(ps), n)]
}
