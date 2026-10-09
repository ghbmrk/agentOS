package corpus

import (
	_ "embed"
	"time"

	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// promptInject is the items of assurance/corpora/promptinject/items.json,
// copied because go:embed cannot reach it, and held byte for byte to one
// rendering of them by tests/test_corpus.py.
// The corpus is part of the signed binary, so the binary's signature is
// its digest and no drive file is read (#515 Security 3; corpus C1).
//
//go:embed promptinject.json
var promptInject []byte

// Items are the embedded corpus's items: every vendored item, since each
// fits one owner text with the code filter's payload (corpus C2).
func Items() ([]loops.CorpusItem, error) { return loops.ParseCorpus(promptInject) }

// Probe is the in-process corpus replay agentosd runs in Loop 2's slot:
// the embedded items through InProcess(c), every interval. It uses no
// guest, no network and no model.
func Probe(interval time.Duration, c owner.Commitments) (*loops.CorpusProbe, error) {
	items, err := Items()
	if err != nil {
		return nil, err
	}
	return &loops.CorpusProbe{Interval: interval, Items: items, Checks: InProcess(c)}, nil
}
