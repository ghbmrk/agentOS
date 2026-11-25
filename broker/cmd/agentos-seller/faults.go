package main

import (
	"io"
	"os"

	"github.com/ghbmrk/agentos/broker/change"
	"golang.org/x/sys/unix"
)

// Fault seams (#6594). Each is the real call. A test swaps one to make a
// step fail that a working disk, file system or tool does not fail on
// cue, and checks that prep or write stops there, or to see a call whose
// effect a file cannot show (a block device's flags, cache drops).
var (
	openFile  = os.Open
	openDev   = os.OpenFile
	statPath  = os.Stat
	statFile  = (*os.File).Stat
	seekFile  = (*os.File).Seek
	syncFile  = (*os.File).Sync
	closeFile = (*os.File).Close
	chmod     = os.Chmod
	copyBuf   = io.CopyBuffer
	newStore  = func() change.Store { return &change.MemStore{} }
	isBlock   = func(m os.FileMode) bool { return m&os.ModeDevice != 0 && m&os.ModeCharDevice == 0 }
	flushBuf  = func(fd int) error { return unix.IoctlSetInt(fd, unix.BLKFLSBUF, 0) }
	fadvise   = unix.Fadvise
)
