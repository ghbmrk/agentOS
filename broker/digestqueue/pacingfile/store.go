// Package pacingfile supplies an opt-in bounded pacing reader, reusing the
// existing change.FileStore durable writer. Parent paths and exclusive writers
// must remain protected by trusted deployment custody; see CONTRACT.md.
package pacingfile

import (
	"errors"
	"io"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
)

var ErrStorage = errors.New("pacingfile: accounting storage unavailable")

type Store struct{ Path string }

var _ grants.PacingStore = Store{}

func (s Store) Save(b []byte) error {
	if len(b) > grants.MaxPacingStateBytes {
		return ErrStorage
	}
	if err := (change.FileStore{Path: s.Path}).Save(b); err != nil {
		return ErrStorage
	}
	return nil
}
func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(grants.MaxPacingStateBytes)+1))
	if err != nil || len(b) > grants.MaxPacingStateBytes {
		return nil, ErrStorage
	}
	return b, nil
}
