package control

import (
	"strings"
	"unicode"
)

// Word is one control word from CH-11's closed set.
type Word string

const (
	WordNone   Word = "" // not a control word: task chat for the agent
	WordStop   Word = "STOP"
	WordResume Word = "RESUME"
	WordStatus Word = "STATUS"
	WordHelp   Word = "HELP"
	WordYes    Word = "YES"
	WordNo     Word = "NO"
	WordUndo   Word = "UNDO"
	WordMore   Word = "MORE"
	// WordUnclear is a message that starts with RESUME, YES, or NO and has
	// digits but fits no grammar. It may hold a code, so it never goes to
	// the agent (CH-10: the agent never sees a code).
	WordUnclear Word = "?"
	WordName    Word = "NAME"
)

// Command is a parsed owner message. For task chat, Word is WordNone and
// Text is what the agent receives; Public is set by a leading PUBLIC.
type Command struct {
	Word   Word
	Args   []string
	Public bool
	Text   string
}

// Parse applies CH-11: a control word counts only when it, with its
// arguments, is the whole message, ignoring case and punctuation. Anything
// else is task chat and keeps its original text.
func Parse(msg string) Command {
	f := words(msg)
	if len(f) > 0 {
		w, args := Word(f[0]), f[1:]
		if argsFit(w, args) {
			if len(args) == 0 {
				args = nil
			}
			return Command{Word: w, Args: args}
		}
		if (w == WordResume || w == WordYes || w == WordNo) && strings.ContainsAny(msg, "0123456789") {
			return Command{Word: WordUnclear}
		}
		if w == "PUBLIC" && len(args) > 0 {
			return Command{Public: true, Text: afterFirstWord(msg)}
		}
	}
	return Command{Text: msg}
}

// words splits msg into upper-cased words, treating punctuation as space.
func words(msg string) []string {
	return strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return ' '
	}, msg))
}

// StopNearMiss reports whether a task message starts or ends with the word
// STOP, like "stop everything" or "please stop". Such a message still goes
// to the agent, and the broker also says how to pause (B4).
func StopNearMiss(msg string) bool {
	f := words(msg)
	return len(f) > 1 && (f[0] == string(WordStop) || f[len(f)-1] == string(WordStop))
}

// argsFit is each word's argument grammar. A message that does not fit is
// task chat, so "stop the newsletter" goes to the agent.
func argsFit(w Word, args []string) bool {
	switch w {
	case WordStop, WordStatus, WordHelp:
		return len(args) == 0
	case WordResume:
		return len(args) == 0 || (len(args) == 1 && digits(args[0]))
	case WordYes:
		return len(args) > 0 && allDigits(args)
	case WordNo:
		return allDigits(args)
	case WordUndo, WordMore:
		return len(args) == 1 && len(args[0]) <= 3 && alnum(args[0])
	case WordName:
		// NAME alone reports the current name; NAME <words...> renames (CH-21).
		return true
	}
	return false
}

// afterFirstWord drops the leading PUBLIC and the punctuation after it,
// keeping the rest of the owner's text as written.
func afterFirstWord(msg string) string {
	s := strings.TrimLeftFunc(msg, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	s = s[len("PUBLIC"):]
	return strings.TrimLeftFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func allDigits(ss []string) bool {
	for _, s := range ss {
		if !digits(s) {
			return false
		}
	}
	return true
}

func alnum(s string) bool {
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return s != ""
}
