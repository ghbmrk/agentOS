// Package changesource connects real pipeline snapshots to the digest collector.
// It has no sender or owner-visibility/outcome path.
package changesource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
)

const ID = "change"

// Source is broker-owned. Never expose its methods or source receipts to guests.
type Source struct{ pipeline *change.Pipeline }

var _ digestqueue.Source = (*Source)(nil)

func New(p *change.Pipeline) (*Source, error) {
	if p == nil {
		return nil, digestqueue.ErrInvalid
	}
	return &Source{pipeline: p}, nil
}
func (s *Source) Peek(ctx context.Context) (*digestqueue.Snapshot, error) {
	if ctx == nil {
		return nil, digestqueue.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snap, err := s.pipeline.PeekDigest()
	if err != nil || snap == nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	receipt, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	out, err := digestqueue.NewSnapshotWithReceipt(ID, snap.Generation, snap.Lines, snap.References, string(receipt))
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func decode(snap digestqueue.Snapshot) (change.DigestSnapshot, error) {
	var receipt change.DigestSnapshot
	if snap.Source != ID {
		return receipt, digestqueue.ErrInvalid
	}
	reconstructed, err := digestqueue.NewSnapshotWithReceipt(ID, snap.Generation, snap.Lines, snap.References, snap.Receipt)
	if err != nil || reconstructed.Hash != snap.Hash {
		return receipt, digestqueue.ErrInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(snap.Receipt))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		return receipt, errors.Join(digestqueue.ErrInvalid, err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return receipt, digestqueue.ErrInvalid
	}
	if receipt.Generation != snap.Generation || !reflect.DeepEqual(receipt.Lines, snap.Lines) || !reflect.DeepEqual(receipt.References, snap.References) {
		return receipt, digestqueue.ErrConflict
	}
	return receipt, nil
}

// Ack binds queue content to the retained issued source receipt before invoking
// the pipeline's durable idempotent acknowledgment. Queue admission must precede
// this call; the Collector enforces that sequencing.
func (s *Source) Ack(ctx context.Context, snap digestqueue.Snapshot) error {
	if ctx == nil {
		return digestqueue.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	receipt, err := decode(snap)
	if err != nil {
		return err
	}
	return s.pipeline.AckDigest(receipt)
}

// Validate checks the receipt's issuance and pipeline pending-invalidation floor.
// It is not a complete send-time forget/UNDO/MORE check or authority decision.
func (s *Source) Validate(ctx context.Context, snap digestqueue.Snapshot) error {
	if ctx == nil {
		return digestqueue.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	receipt, err := decode(snap)
	if err != nil {
		return err
	}
	return s.pipeline.ValidateDigest(receipt)
}
