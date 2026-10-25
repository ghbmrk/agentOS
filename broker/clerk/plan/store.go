package plan

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Store is a plan login's one sealed value (CLK-1, STO-2): the login, its
// account and any stop, sealed under a key that never leaves the Sealer and
// bound to the plan's name, so a value sealed for another plan does not
// open. No method returns the plaintext: it is opened inside this package,
// for one request, and wiped after.
type Store struct {
	s     clerk.Sealer
	write func(atRest []byte) error
	mu    sync.Mutex // also serializes writes, so the last one written is the last one put
	blob  []byte     // nil: nothing stored
}

// NewStore makes an empty store. write, if not nil, makes it durable: every
// change hands it the whole at-rest form and returns only once it returns,
// so it must return only when the bytes are on disk, replaced atomically.
// nil keeps the store in memory only, for tests.
func NewStore(s clerk.Sealer, write func(atRest []byte) error) *Store {
	return &Store{s: s, write: write}
}

// Load takes the at-rest form a durable store wrote; empty is nothing
// stored. It is opened, and checked, when New binds it to its plan.
func (s *Store) Load(atRest []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blob = nil
	if len(atRest) > 0 {
		s.blob = append([]byte(nil), atRest...)
	}
}

// MarshalBinary is the at-rest form: the sealed blob alone.
func (s *Store) MarshalBinary() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.blob...), nil
}

func aad(name string) []byte { return []byte("agentos/clerk/plan/" + name) }

// put seals plain for name, or empties the store for nil. With a durable
// store it returns only after the at-rest form is written; if sealing or
// writing fails, the store is unchanged.
func (s *Store) put(name string, plain []byte) error {
	var blob []byte
	if plain != nil {
		b, err := s.s.Seal(plain, aad(name))
		if err != nil {
			return err
		}
		blob = b
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.write != nil {
		if err := s.write(blob); err != nil {
			return err
		}
	}
	s.blob = blob
	return nil
}

// open opens the value for fn and wipes the plaintext after it returns.
// An empty store calls nothing and is no error.
func (s *Store) open(name string, fn func(plain []byte) error) error {
	s.mu.Lock()
	blob := s.blob
	s.mu.Unlock()
	if blob == nil {
		return nil
	}
	plain, err := s.s.Open(blob, aad(name))
	if err != nil {
		return errors.New("clerk: the plan login does not open")
	}
	defer clear(plain)
	return fn(plain)
}

// The answer's redaction mark, as the clerk's own.
var redacted = []byte("[redacted]")

var methRE = regexp.MustCompile(`^[A-Z]+$`)

// guarded is the transport package clerk gives its own clerks: no proxy from
// the environment, no cookie jar, no redirects, every dial through the
// guard, and Go's default key exchange, X25519MLKEM768 first. It is repeated
// here rather than exported from package clerk, so this package adds no
// line to the trusted core (KRN-2cap).
func guarded(guard *netguard.Policy, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         guard.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
