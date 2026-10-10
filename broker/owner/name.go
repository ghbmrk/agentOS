package owner

import (
	"fmt"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/boxname"
)

// nameCmd is a NAME message (CH-11, CH-21).
//
//	NAME              replies with the current name
//	NAME name         asks to rename; confirmed by a texted code
//	NAME name code    renames with a code-generator code
//	NAME code         confirms a rename with the texted code
type nameCmd struct {
	ask  bool
	name string // as typed, before boxname.Check
	code string
}

// renameReq is a rename waiting for NAME <code>. code is "" when only a
// strong code confirms it (the low tier is locked).
type renameReq struct {
	name    string
	code    string
	expires time.Time
	wrong   int
}

// trimEnd drops the closing punctuation a phone adds to a sentence.
func trimEnd(s string) string { return strings.TrimRight(s, ".!? ") }

// parseName reports whether text is a NAME command. Like every control
// word it counts only as the whole message: the argument must be a code
// or a name of boxname.Shape, so "name the file report.pdf" is chat.
func parseName(text string) (nameCmd, bool) {
	s := trimEnd(strings.TrimSpace(text))
	word, rest, _ := strings.Cut(s, " ")
	if !strings.EqualFold(strings.TrimRight(word, ":,"), "NAME") {
		return nameCmd{}, false
	}
	rest = strings.TrimSpace(rest)
	switch {
	case rest == "":
		return nameCmd{ask: true}, true
	case isCode(rest):
		return nameCmd{code: rest}, true
	}
	if n, code, ok := trailingCode(rest); ok && boxname.Shape(trimEnd(n)) {
		return nameCmd{name: trimEnd(n), code: code}, true
	}
	if boxname.Shape(rest) {
		return nameCmd{name: rest}, true
	}
	return nameCmd{}, false
}

// Name is the box's name, "" before one is set (CH-21).
func (c *Channel) Name() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes.st.Name
}

// nameLocked handles NAME (CH-11). A rename widens how the box presents
// itself to third parties, so it takes effect only with a code-generator
// code in the same message, or in an unlocked session on NAME and a code
// texted to the owner's number in fixed wording: an unlocked session
// proves the owner was here, not who sent this NAME, and a spoofer never
// sees the texted code. In a locked session NAME is held for the unlock.
func (c *Channel) nameLocked(text string, n nameCmd, now time.Time, unlocked bool) route {
	if n.ask {
		reply := "I have no name yet. To give me one, send NAME and the name."
		if c.codes.st.Name != "" {
			reply = fmt.Sprintf("My name is %q.", c.codes.st.Name)
		}
		return route{replies: []string{reply}, limited: !unlocked}
	}
	if n.name == "" {
		return route{replies: []string{c.confirmRenameLocked(n.code, now, unlocked)}, limited: true}
	}
	name, err := boxname.Check(n.name, c.cfg.OwnerName)
	if err != nil {
		return route{replies: []string{"I can't take that name: " + err.Error() + ". Nothing changed."}, limited: true}
	}
	if n.code != "" {
		res, locked, err := c.codes.checkStrong(n.code, now, strongOpts{unlock: c.cfg.UnlockFor, count: true})
		switch {
		case err != nil:
			return route{replies: []string{c.codeErr(err)}, limited: true}
		case res != strongOK:
			return route{replies: []string{"Wrong code. Nothing changed." + lockNote(locked)}, limited: true}
		}
		c.held = nil
		return route{replies: []string{c.renameLocked(name)}}
	}
	if !unlocked {
		return c.lockedLocked(text, "", now)
	}
	return route{replies: []string{c.askRenameLocked(name, now)}, limited: true}
}

// askRenameLocked replaces any waiting rename with one for name and
// returns its fixed-wording confirmation.
func (c *Channel) askRenameLocked(name string, now time.Time) string {
	c.rename = &renameReq{name: name, expires: now.Add(c.cfg.CodeTTL)}
	if !c.codes.st.LowLocked {
		c.rename.code = c.codes.textedCode()
	}
	q := fmt.Sprintf("Change my name to %q?", name)
	if old := c.codes.st.Name; old != "" {
		q = fmt.Sprintf("Change my name from %q to %q?", old, name)
	}
	if c.rename.code == "" {
		return q + " To confirm, reply NAME and a code from your code generator" + c.gridOr() + "."
	}
	return fmt.Sprintf("%s To confirm, reply NAME %s within %s.", q, c.rename.code, dur(c.cfg.CodeTTL))
}

// confirmRenameLocked checks NAME <code> against the waiting rename. The
// texted code counts only in an unlocked session; otherwise only a strong
// code confirms.
func (c *Channel) confirmRenameLocked(code string, now time.Time, unlocked bool) string {
	p := c.rename
	if p == nil || !now.Before(p.expires) {
		c.rename = nil
		return "No rename is waiting. Send NAME and the new name."
	}
	texted := p.code
	if !unlocked {
		texted = ""
	}
	ok, locked, msg := c.checkLocked(texted, code, now)
	switch {
	case msg != "":
		return msg
	case !ok:
		p.wrong++
		if p.wrong >= WrongPerRequest {
			c.rename = nil
			return "Wrong code 3 times; it is void. Nothing changed." + lockNote(locked)
		}
		return "Wrong code. Nothing changed. Reply NAME <code>." + lockNote(locked)
	}
	return c.renameLocked(p.name)
}

// renameLocked saves name, which has passed boxname.Check.
func (c *Channel) renameLocked(name string) string {
	c.rename = nil
	if err := c.codes.commit(func(s *State) { s.Name = name }); err != nil {
		return "Could not save the new name. Nothing changed. Try again."
	}
	return fmt.Sprintf("Done. My name is now %q.", name)
}
