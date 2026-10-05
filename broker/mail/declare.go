package mail

import (
	"fmt"
	"sort"

	"github.com/ghbmrk/agentos/broker/verb"
)

// Tool is the adapter's tool identity, and Connections its connection
// types (ADP-1, ADP-3). The provider's API route is a later adapter
// version; IMAP and SMTP reach every provider, Gmail included.
const (
	Tool    = "mail"
	Version = "1"
)

var Connections = []string{"imap+smtp"}

// Operations (actions on the journal). Every one names its source message
// by Message-ID in the "record" param, except a new message.
const (
	OpDraft      = "mail.draft"
	OpSend       = "mail.send"
	OpReply      = "mail.reply"
	OpArchive    = "mail.archive"
	OpUnarchive  = "mail.unarchive"
	OpMove       = "mail.move"
	OpLabel      = "mail.label"
	OpUnlabel    = "mail.unlabel"
	OpMarkRead   = "mail.mark_read"
	OpMarkUnread = "mail.mark_unread"
	OpStar       = "mail.star"
	OpUnstar     = "mail.unstar"
	OpDelete     = "mail.delete"
	OpReportSpam = "mail.report_spam"
	// OpDeliver mails the owner an agent reply too private for a text
	// (CH-20). Only the broker submits it, to the destination the owner
	// set; its one recipient is the account's own address.
	OpDeliver = "mail.deliver"
)

// DeliverSubject is the fixed subject of an OpDeliver message: nothing
// the agent writes is in it.
const DeliverSubject = "Your agent's reply"

// Params.
const (
	ParamRecord  = "record"  // the source message's Message-ID
	ParamFolder  = "folder"  // where the record is, if not the inbox or archive
	ParamTo      = "to"      // a move's target folder
	ParamLabel   = "label"   // a label's name
	ParamSubject = "subject" // a new message's subject
	ParamBody    = "body"    // plain text
)

// Op is one declared operation: its verb from the broker's list (ADP-2),
// its inverse when the verb is organize, whether it can hide a message
// from the owner (archive, move out of the inbox, mark read), and the
// params it takes.
type Op struct {
	Name     string
	Verb     string
	Inverse  string
	Hides    bool
	Required []string
	Optional []string
}

var ops = []Op{
	{Name: OpDeliver, Verb: verb.Share, Required: []string{ParamBody}},
	{Name: OpDraft, Verb: verb.Draft, Required: []string{ParamBody}, Optional: []string{ParamSubject, ParamRecord}},
	{Name: OpSend, Verb: verb.Send, Required: []string{ParamSubject, ParamBody}},
	// A reply carries exactly record and body, so an ADP-11 reply rule can
	// match it (grants GR6).
	{Name: OpReply, Verb: verb.Send, Required: []string{ParamRecord, ParamBody}},
	{Name: OpArchive, Verb: verb.Organize, Inverse: OpUnarchive, Hides: true, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	{Name: OpUnarchive, Verb: verb.Organize, Inverse: OpArchive, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	{Name: OpMove, Verb: verb.Organize, Inverse: OpMove, Hides: true, Required: []string{ParamRecord, ParamTo}, Optional: []string{ParamFolder}},
	{Name: OpLabel, Verb: verb.Organize, Inverse: OpUnlabel, Required: []string{ParamRecord, ParamLabel}, Optional: []string{ParamFolder}},
	{Name: OpUnlabel, Verb: verb.Organize, Inverse: OpLabel, Required: []string{ParamRecord, ParamLabel}, Optional: []string{ParamFolder}},
	{Name: OpMarkRead, Verb: verb.Organize, Inverse: OpMarkUnread, Hides: true, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	{Name: OpMarkUnread, Verb: verb.Organize, Inverse: OpMarkRead, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	{Name: OpStar, Verb: verb.Organize, Inverse: OpUnstar, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	{Name: OpUnstar, Verb: verb.Organize, Inverse: OpStar, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	// Moving to trash cannot be undone inside the account once the
	// provider empties it, and reporting spam tells the provider:
	// delete-remote (ADP-2).
	{Name: OpDelete, Verb: verb.DeleteRemote, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
	{Name: OpReportSpam, Verb: verb.DeleteRemote, Required: []string{ParamRecord}, Optional: []string{ParamFolder}},
}

var byName = func() map[string]Op {
	m := map[string]Op{}
	for _, o := range ops {
		m[o.Name] = o
	}
	return m
}()

// Ops returns the declaration, sorted by name.
func Ops() []Op {
	out := append([]Op(nil), ops...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Declared is the declaration as the grants gate takes it
// (grants.Config.Declared[executor]): each operation's verb.
func Declared() map[string]string {
	m := map[string]string{}
	for _, o := range ops {
		m[o.Name] = o.Verb
	}
	return m
}

// Validate checks a declaration against ADP-2: every verb is on the
// broker's list, and an operation maps to organize only if it declares an
// inverse that is itself a declared organize operation.
func Validate(decl []Op) error {
	m := map[string]Op{}
	for _, o := range decl {
		if _, dup := m[o.Name]; dup || o.Name == "" {
			return fmt.Errorf("mail: operation %q declared twice or unnamed", o.Name)
		}
		m[o.Name] = o
	}
	for _, o := range decl {
		if !verb.Valid(o.Verb) {
			return fmt.Errorf("mail: %s: verb %q is not on the broker's list (ADP-2)", o.Name, o.Verb)
		}
		if o.Verb != verb.Organize {
			continue
		}
		inv, ok := m[o.Inverse]
		if o.Inverse == "" || !ok || inv.Verb != verb.Organize {
			return fmt.Errorf("mail: %s maps to organize without a declared organize inverse (ADP-2)", o.Name)
		}
	}
	return nil
}

func init() {
	if err := Validate(ops); err != nil {
		panic(err)
	}
}

// checkParams refuses a param the operation does not take and a missing
// or non-string one, so nothing an agent adds is silently ignored.
func checkParams(o Op, params map[string]any) (map[string]string, error) {
	out := map[string]string{}
	allowed := map[string]bool{}
	for _, k := range o.Required {
		allowed[k] = true
	}
	for _, k := range o.Optional {
		allowed[k] = true
	}
	for k, v := range params {
		s, ok := v.(string)
		if !allowed[k] || !ok {
			return nil, fmt.Errorf("mail: %s does not take param %q", o.Name, k)
		}
		out[k] = s
	}
	for _, k := range o.Required {
		if out[k] == "" {
			return nil, fmt.Errorf("mail: %s needs param %q", o.Name, k)
		}
	}
	return out, nil
}
