package seal

import "slices"

// StoreKey exposes the store key to the canary test, which must find no
// trace of it on the drive.
func StoreKey(s *Store) []byte { return append([]byte(nil), s.key.Get()...) }

// FailDirSync makes every directory sync fail until the returned func runs.
func FailDirSync(err error) (restore func()) {
	old := syncDir
	syncDir = func(string) error { return err }
	return func() { syncDir = old }
}

// FailWrite makes every write fail before its rename until the returned
// func runs.
func FailWrite(err error) (restore func()) {
	old := writeTemp
	writeTemp = func(string, []byte) (string, error) { return "", err }
	return func() { writeTemp = old }
}

// Entries is the store's own entry map, not a copy, so a test can see
// Close wipe the values it held.
func Entries(s *Store) map[string][]byte { return s.entries.Get() }

// Replace puts a new slot for f in place of slot id in one write: a new
// passphrase or recovery key (REC-4), or a TPM slot sealed again. The old
// slot no longer opens the store once Replace returns.
func (s *Store) Replace(id string, f Factor) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return "", err
	}
	i := s.find(id)
	if i < 0 {
		return "", ErrNoSlot
	}
	sl, err := makeSlot(s.f.ID, s.key.Get(), f)
	if err != nil {
		return "", err
	}
	slots := slices.Clone(s.f.Slots)
	slots[i] = sl
	return s.committed(sl.ID, s.commit(slots, s.entries.Get()))
}
