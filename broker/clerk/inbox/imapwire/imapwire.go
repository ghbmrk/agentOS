// Package imapwire is the typed wire between the mail clerk and its IMAP
// connection process (KRN-2, #2937 gap 2). The clerk signs in and relays
// the session's bytes; the connection process alone runs the IMAP parser
// over them and answers each typed request with typed data. The wire is
// length-prefixed JSON frames and links no IMAP code, so the clerk can
// speak it without the parser. What the connection answers is untrusted:
// the clerk checks it (imapsmtp).
package imapwire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Role is a folder's special use (RFC 6154), or "" for none.
type Role string

// The roles the clerk reads.
const (
	Inbox   Role = "inbox"
	Archive Role = "archive"
	Drafts  Role = "drafts"
	Sent    Role = "sent"
	Trash   Role = "trash"
	Junk    Role = "junk"
	All     Role = "all"
)

// Known says whether r is one of the roles above or none.
func (r Role) Known() bool {
	switch r {
	case "", Inbox, Archive, Drafts, Sent, Trash, Junk, All:
		return true
	}
	return false
}

// Folder is one selectable folder.
type Folder struct {
	Name string
	Role Role
}

// Ref names one message by its full identity: its folder, the folder's UID
// validity when the UID was read, and the UID. Under another validity the
// same UID may be another message, so every change is checked against it.
type Ref struct {
	Folder   string
	Validity uint32
	UID      uint32
}

// Message is one message as the server holds it: its reference, its flags
// and its first MaxFetch bytes, read without marking it read.
type Message struct {
	Ref
	Flags []string
	Raw   []byte
}

// Mark is what a folder's STATUS says of its contents. It changes when mail
// arrives or leaves, when the number of unread mails changes, and, where the
// server has CONDSTORE (RFC 7162), when any flag changes; without CONDSTORE
// one mail read and another marked unread together leave it as it was.
type Mark struct {
	Folder                           string
	Validity, Next, Messages, Unseen uint32
	ModSeq                           string // HIGHESTMODSEQ, "" without CONDSTORE
}

// Head is one read mail's From and Message-ID headers and its INTERNALDATE,
// as a Seen batch answers them.
type Head struct {
	UID     uint32
	Header  []byte
	Arrived time.Time
}

// The requests, one per typed call. Each names the IMAP commands it may
// send; imapsmtp's filter enforces that on the relayed bytes.
const (
	OpFolders    = "folders"     // the selectable folders
	OpUIDs       = "uids"        // Folder's validity and every UID in it
	OpFetch      = "fetch"       // UIDs of Folder at Validity, by BODY.PEEK
	OpSeenSearch = "seen-search" // select Folder and search its read mail
	OpSeenBatch  = "seen-batch"  // the headers of UIDs in the selected folder
	OpSubject    = "subject"     // the Subject of UIDs[0] in the selected folder
	OpNext       = "next"        // Folder's validity and next UID
	OpFind       = "find"        // the messages in Folder whose Message-ID holds ID
	OpSetFlags   = "setflags"    // Add and Remove on one message
	OpMove       = "move"        // one message to To
	OpMarks      = "marks"       // every folder's Mark
	OpEnsure     = "ensure"      // create Folder if absent (the old core only)
	OpAppend     = "append"      // store Raw in Folder (the old core only)
)

// Request is one typed call from the clerk.
type Request struct {
	Op       string    `json:"op"`
	Folder   string    `json:"folder,omitempty"`
	Validity uint32    `json:"validity,omitempty"`
	From     uint32    `json:"from,omitempty"`
	UIDs     []uint32  `json:"uids,omitempty"`
	ID       string    `json:"id,omitempty"`
	Add      []string  `json:"add,omitempty"`
	Remove   []string  `json:"remove,omitempty"`
	To       string    `json:"to,omitempty"`
	Flags    []string  `json:"flags,omitempty"`
	Date     time.Time `json:"date,omitzero"`
	Raw      []byte    `json:"raw,omitempty"`
	MaxFetch int       `json:"maxfetch,omitempty"`
}

// Response is the connection's answer to one Request. Err is "" on success,
// or the code of what failed (Code).
type Response struct {
	Err      string           `json:"err,omitempty"`
	Long     *LongHeaderError `json:"long,omitempty"`
	Folders  []Folder         `json:"folders,omitempty"`
	Validity uint32           `json:"validity,omitempty"`
	Next     uint32           `json:"next,omitempty"`
	UIDs     []uint32         `json:"uids,omitempty"`
	Messages []Message        `json:"messages,omitempty"`
	Heads    []Head           `json:"heads,omitempty"`
	Marks    []Mark           `json:"marks,omitempty"`
	Subject  string           `json:"subject,omitempty"`
}

// ErrNoMove is returned before acting by a server without MOVE.
var ErrNoMove = errors.New("imapsmtp: the server does not support MOVE")

// ErrValidity is returned before acting when a folder's UID validity is
// not the one a reference was read under.
var ErrValidity = errors.New("imapsmtp: the folder was renumbered since it was read")

// ErrNoUIDNext is returned for a folder whose SELECT gave no UID validity
// or next UID, both of which RFC 3501 requires: what arrives in it from now
// on cannot be told from what was there.
var ErrNoUIDNext = errors.New("imapsmtp: the server did not give the folder's next UID")

// ErrPartialStatus fails Marks when a folder's STATUS reply leaves out an
// item asked for: a count missing reads as 0, which is a count, so the mark
// would stay the same however the folder changed.
var ErrPartialStatus = errors.New("imapsmtp: a STATUS reply left out an item asked for")

// ErrUnanswered is a FETCH that left a searched message, still there and
// still read, without its header, and ErrLongHeader headers longer than
// headMax: either would leave a mail out of what Seen found.
var (
	ErrUnanswered = errors.New("imapsmtp: the server did not answer for every message")
	ErrLongHeader = errors.New("imapsmtp: a mail's headers are too long to read")
)

// ErrFailed is any other failure the connection reports: a command the
// server refused, a reply it could not read, or a code the clerk does not
// know. It carries none of the server's words.
var ErrFailed = errors.New("imapsmtp: the mail server's session failed")

// LongHeaderError is ErrLongHeader for one mail, named so the owner can find
// it: its folder, its INTERNALDATE (zero if the server sent none) and its
// Subject, read on its own under subjectMax bytes, since its other headers
// are what was too long. Error names the folder, arrival and UID, never the
// subject: that is the mail's content, for the owner's eyes, not a log.
type LongHeaderError struct {
	Folder  string
	Arrived time.Time
	UID     uint32
	Subject string
}

func (e *LongHeaderError) Error() string {
	at := "at an unknown time"
	if !e.Arrived.IsZero() {
		at = e.Arrived.Format("2006-01-02 15:04 -0700")
	}
	return fmt.Sprintf("%v: the mail in %s that arrived %s (UID %d)", ErrLongHeader, e.Folder, at, e.UID)
}

func (e *LongHeaderError) Unwrap() error { return ErrLongHeader }

var codes = map[string]error{"nomove": ErrNoMove, "validity": ErrValidity, "nouidnext": ErrNoUIDNext,
	"partialstatus": ErrPartialStatus, "unanswered": ErrUnanswered, "longheader": ErrLongHeader}

// Code is err's code on the wire: "" for nil, a sentinel's name, or
// "failed" for anything else.
func Code(err error) string {
	if err == nil {
		return ""
	}
	for c, e := range codes {
		if errors.Is(err, e) {
			return c
		}
	}
	return "failed"
}

// Err is the error a code names. An unknown code is ErrFailed, never
// success.
func Err(code string) error {
	if code == "" {
		return nil
	}
	if e, ok := codes[code]; ok {
		return e
	}
	return ErrFailed
}

// ErrFrame is a frame past its reader's bound, or one that is not JSON.
var ErrFrame = errors.New("imapwire: a frame is too large or malformed")

// Write writes v as one frame: a 4-byte big-endian length, then its JSON.
func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if uint64(len(b)) > 1<<32-1 {
		return ErrFrame
	}
	buf := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	_, err = w.Write(append(buf, b...))
	return err
}

// Read reads one frame of at most max bytes into v. A longer frame fails
// before any of it is read past its length.
func Read(r io.Reader, max int64, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	l := int64(binary.BigEndian.Uint32(n[:]))
	if l > max {
		return ErrFrame
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	if json.Unmarshal(b, v) != nil {
		return ErrFrame
	}
	return nil
}
