package recall

import (
	"errors"
	"os"
)

var errFault = errors.New("recall test: injected fault")

// faultFile is a store file that fails on cue: the next Write keeps only
// keep bytes and fails (keep < 0: writes work), the next failSyncs Syncs
// fail, and Truncate fails while failTruncate is set.
type faultFile struct {
	*os.File
	keep         int
	failSyncs    int
	failTruncate bool
}

func (f *faultFile) Write(b []byte) (int, error) {
	if f.keep < 0 {
		return f.File.Write(b)
	}
	n, _ := f.File.Write(b[:min(f.keep, len(b))])
	f.keep = -1
	return n, errFault
}

func (f *faultFile) Sync() error {
	if f.failSyncs > 0 {
		f.failSyncs--
		return errFault
	}
	return f.File.Sync()
}

func (f *faultFile) Truncate(size int64) error {
	if f.failTruncate {
		return errFault
	}
	return f.File.Truncate(size)
}

// fault wraps s's file in a faultFile, set up by set, and returns it.
func fault(s *FileStore, set func(*faultFile)) *faultFile {
	f := &faultFile{File: s.f.(*os.File), keep: -1}
	set(f)
	s.f = f
	return f
}

// FaultNextAppend makes s's next append write only keep bytes of its line
// and fail, as a full disk can (for tests outside the package).
func FaultNextAppend(s *FileStore, keep int) {
	fault(s, func(f *faultFile) { f.keep = keep })
}
