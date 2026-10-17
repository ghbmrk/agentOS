package journal

import "fmt"

// RecPicture journals a picture or file texted to the owner line (an MMS
// notice) that the box did not open (CH-12).
const RecPicture RecordType = "picture"

// The senders a PictureNote names: never the number itself.
const (
	PictureOwner = "owner"
	PictureOther = "other"
)

// PictureNote is one picture or file texted to the owner line.
type PictureNote struct {
	From string `json:"from"`
}

func (n PictureNote) valid() bool { return n.From == PictureOwner || n.From == PictureOther }

// RecordPicture journals a picture texted to the box. It is audit only: it
// changes no intent, and STOP does not hold it.
func (e *Engine) RecordPicture(n PictureNote) error {
	if !n.valid() {
		return fmt.Errorf("%w: picture note needs from owner or other", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	return e.commit(Record{Type: RecPicture, Picture: &n})
}
