// Package secret holds a key so that no print shows it (CLK-1, DECOY-b-8).
// It links nothing, so every trusted-core holder of a key can use it: the
// unlock step's hand-off, the sealed store and its factors, the TPM
// counter's auth and each clerk's key (#4759, #4833).
package secret

// Secret holds a key behind a pointer to a pointer, which fmt prints as an
// address in every verb and at any depth, while reflect.DeepEqual compares
// through it, so a line that formats a holder shows no key (the #4719
// rule). A copy shares the key; the zero Secret holds none. Drop it only
// after every reader is done: Drop while another goroutine reads a shared
// copy is a data race.
type Secret[T any] struct{ p **T }

// Hide holds v.
func Hide[T any](v T) Secret[T] { return Secret[T]{new(&v)} }

// Get is the key held, or T's zero value.
func (s Secret[T]) Get() T { return *s.Ref() }

// Ref points at the key held, or, for the zero Secret, at a zero value
// that nothing else holds.
func (s Secret[T]) Ref() *T {
	if s.p == nil || *s.p == nil {
		return new(T)
	}
	return *s.p
}

// Drop clears s's bytes and empties every copy of it.
func Drop[T ~[]byte](s Secret[T]) {
	clear(*s.Ref())
	if s.p != nil {
		*s.p = nil
	}
}
