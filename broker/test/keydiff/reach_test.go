package keydiff

// REQ: EVL-1, KEY-2, KEY-3

// The predicate-reach check (#2989). Each library mutant below drops one
// predicate of broker/kernel/key, or moves one bound by one, and the sweep
// must find a seed where the mutated library and keycheck disagree. A rule
// the generator stops reaching, or one keycheck does not judge, fails here
// instead of passing quietly. The list is the one the retired Go reference
// model (refmodel_test.go) guarded with its own planted bugs, read against
// the library: where the model had two predicates for one of the library's
// (a verbs caveat narrowed against the root and against earlier caveats; a
// step's verb against the root's verbs and a verbs caveat), the library's
// one predicate carries one mutant. The model's negative-hold bug has no
// library mutant: the library's base hold starts at 0, so a negative one
// already loosens it, and dropping the sign check changes no verdict.
//
// Each mutant builds the package with `go test -overlay`, so the tree is
// never edited. Set KEYDIFF_REACH and KEYCHECK to run it. Each sweep runs
// the fixed seeds from 0 and stops at the first disagreement, so only a
// mutant that survives runs all KEYDIFF_REACH_CASES of them (default 100000).
// So first the unmutated library must agree with keycheck over that whole
// range (#3002): a real disagreement at some seed would otherwise count every
// mutant that survives up to it as killed.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// libMutant replaces old, which must occur once in broker/kernel/key/file,
// with new. why says what the planted bug lets through.
type libMutant struct {
	name, why, file string
	old, new        string
}

var libMutants = []libMutant{
	{"issuer", "a root issued by a non-passkey", "key.go",
		"if !In(owners, k.Root.Owner) {",
		"if false {"},
	{"root-sig", "a root with a bad signature", "key.go",
		"if owners != nil && !ed25519.Verify(r.Owner,",
		"if false && !ed25519.Verify(r.Owner,"},
	{"root-clerk", "a root for no clerk", "key.go",
		" || r.Clerk == \"\" || ",
		" || "},
	{"root-verbs", "a root with no verbs", "key.go",
		" || len(r.Verbs) == 0 || ",
		" || "},
	{"root-verb-valid", "a root verb off the list", "key.go",
		"if !Valid(v) {",
		"if false {"},
	{"root-canonical", "a root's verbs unsorted or duplicated", "key.go",
		"if !canonical(vs) {",
		"if false {"},
	{"link-count", "a chain longer than MaxLinks", "key.go",
		" || len(k.Links) > MaxLinks {",
		" {"},
	{"first-signer", "a first link signed by a non-passkey", "key.go",
		"if owners != nil && !signedBy(holder, owners, linkMsg(prev, l), l.Sig) {",
		"if owners != nil && holder != nil && !signedBy(holder, owners, linkMsg(prev, l), l.Sig) {"},
	{"link-sig", "a later link signed by neither the holder nor a passkey", "key.go",
		"if owners != nil && !signedBy(holder, owners, linkMsg(prev, l), l.Sig) {",
		"if owners != nil && holder == nil && !signedBy(holder, owners, linkMsg(prev, l), l.Sig) {"},
	{"narrow-keeps-holder", "a passkey's narrowing that hands the key on", "key.go",
		"if p == nil || !bytes.Equal(l.Holder, holder) {",
		"if p == nil {"},
	{"first-expiry", "a first link with no expiry", "key.go",
		"return exp && spend",
		"return spend"},
	{"first-spend-day", "a first link with no daily spend cap", "key.go",
		"return exp && spend",
		"return exp"},
	{"use-bare-root", "a bare root's use signed by a non-passkey", "key.go",
		"if !signedBy(k.holder(), owners, useMsg(v.ID(), use), sig) {",
		"if k.holder() != nil && !signedBy(k.holder(), owners, useMsg(v.ID(), use), sig) {"},
	{"use-tip", "a use not signed by the tip's holder", "key.go",
		"if !signedBy(k.holder(), owners, useMsg(v.ID(), use), sig) {",
		"if k.holder() == nil && !signedBy(k.holder(), owners, useMsg(v.ID(), use), sig) {"},
	{"verbs-canonical", "an unsorted, duplicated or nil verbs set", "key.go",
		"return narrowSet(&l.Verbs, c, \"verbs\")",
		"return narrowSet(&l.Verbs, Caveat{Kind: c.Kind, Set: set(c.Set)}, \"verbs\")"},
	{"content-canonical", "an unsorted, duplicated or nil content set", "key.go",
		"return narrowSet(&l.Content, c, \"content\")",
		"return narrowSet(&l.Content, Caveat{Kind: c.Kind, Set: set(c.Set)}, \"content\")"},
	{"labels-canonical", "an unsorted, duplicated or nil labels set", "key.go",
		"return narrowSet(&l.Labels, c, \"labels\")",
		"return narrowSet(&l.Labels, Caveat{Kind: c.Kind, Set: set(c.Set)}, \"labels\")"},
	{"arg-named", "an arg bound naming no argument", "key.go",
		"if b == nil || b.Name == \"\" ||",
		"if b == nil ||"},
	{"arg-oneof-canonical", "an arg set not canonical", "key.go",
		"(b.OneOf != nil && !canonical(b.OneOf)) ||",
		"false ||"},
	{"arg-min-max", "an arg bound with min above max", "key.go",
		"(b.Min != nil && b.Max != nil && *b.Min > *b.Max)",
		"false"},
	{"cap-non-neg", "a negative cap", "key.go",
		"if c.N < 0 {\n\t\t\treturn fmt.Errorf(\"%w: negative cap\"",
		"if false {\n\t\t\treturn fmt.Errorf(\"%w: negative cap\""},
	{"task-shape", "a task caveat naming no task or two", "key.go",
		"if len(c.Set) != 1 || c.Set[0] == \"\" {",
		"if len(c.Set) == 0 {"},
	{"hold-order", "a novelty hold shorter than the base hold", "key.go",
		"if c.N < 0 || c.M < c.N {",
		"if c.N < 0 {"},
	{"unknown-kind", "a caveat of no known kind", "key.go",
		"default:\n\t\treturn ErrUnknownKind",
		"default:\n\t\treturn nil"},
	{"verbs-tighter", "a verbs caveat wider than the root or an earlier one", "key.go",
		"return narrowSet(&l.Verbs, c, \"verbs\")",
		"if !canonical(c.Set) {\n\t\t\treturn ErrMalformed\n\t\t}\n\t\tl.Verbs = c.Set\n\t\treturn nil"},
	{"content-tighter", "a later content set wider", "key.go",
		"return narrowSet(&l.Content, c, \"content\")",
		"if !canonical(c.Set) {\n\t\t\treturn ErrMalformed\n\t\t}\n\t\tl.Content = c.Set\n\t\treturn nil"},
	{"labels-tighter", "a later labels set wider", "key.go",
		"return narrowSet(&l.Labels, c, \"labels\")",
		"if !canonical(c.Set) {\n\t\t\treturn ErrMalformed\n\t\t}\n\t\tl.Labels = c.Set\n\t\treturn nil"},
	{"arg-oneof-tighter", "a later arg set dropped or widened", "key.go",
		"if old.OneOf != nil && (b.OneOf == nil || !subset(b.OneOf, old.OneOf)) {",
		"if false {"},
	{"arg-min-tighter", "a later arg min dropped or lowered", "key.go",
		"if old.Min != nil && (b.Min == nil || *b.Min < *old.Min) {",
		"if false {"},
	{"arg-max-tighter", "a later arg max dropped or raised", "key.go",
		"if old.Max != nil && (b.Max == nil || *b.Max > *old.Max) {",
		"if false {"},
	{"expiry-tighter", "a later expiry", "key.go",
		"if l.NotAfter != nil && c.N > *l.NotAfter {",
		"if false {"},
	{"task-tighter", "a later link moving the key to another task", "key.go",
		"if l.Task != \"\" && l.Task != c.Set[0] {",
		"if false {"},
	{"hold-base-tighter", "a later base hold shorter", "key.go",
		"if c.N < l.HoldBase || c.M < l.HoldNovelty {",
		"if c.M < l.HoldNovelty {"},
	{"hold-novelty-tighter", "a later novelty hold shorter", "key.go",
		"if c.N < l.HoldBase || c.M < l.HoldNovelty {",
		"if c.N < l.HoldBase {"},
	{"spend-task-tighter", "a later spend-task cap raised", "key.go",
		"if o.Kind == c.Kind && c.N > o.N {",
		"if o.Kind == c.Kind && c.N > o.N && c.Kind != KSpendTask {"},
	{"spend-day-tighter", "a later spend-day cap raised", "key.go",
		"if o.Kind == c.Kind && c.N > o.N {",
		"if o.Kind == c.Kind && c.N > o.N && c.Kind != KSpendDay {"},
	{"rate-day-tighter", "a later rate-day cap raised", "key.go",
		"if o.Kind == c.Kind && c.N > o.N {",
		"if o.Kind == c.Kind && c.N > o.N && c.Kind != KRateDay {"},
	{"rate-recipient-tighter", "a later rate-recipient cap raised", "key.go",
		"if o.Kind == c.Kind && c.N > o.N {",
		"if o.Kind == c.Kind && c.N > o.N && c.Kind != KRateRecipient {"},
	{"uses-tighter", "a later uses cap raised", "key.go",
		"if o.Kind == c.Kind && c.N > o.N {",
		"if o.Kind == c.Kind && c.N > o.N && c.Kind != KUses {"},
	{"derive-verbs", "a verbs caveat not narrowing the reported verbs", "key.go",
		"return narrowSet(&l.Verbs, c, \"verbs\")",
		"cur := l.Verbs\n\t\treturn narrowSet(&cur, c, \"verbs\")"},
	{"derive-expiry", "the first expiry reported, not the earliest", "key.go",
		"n := c.N\n\t\tl.NotAfter = &n",
		"n := c.N\n\t\tif l.NotAfter == nil {\n\t\t\tl.NotAfter = &n\n\t\t}"},
	{"derive-hold", "the first base hold reported, not the longest", "key.go",
		"l.HoldBase, l.HoldNovelty = c.N, c.M",
		"if l.HoldBase == 0 {\n\t\t\tl.HoldBase = c.N\n\t\t}\n\t\tl.HoldNovelty = c.M"},
	{"derive-novelty", "the first novelty hold reported, not the longest", "key.go",
		"l.HoldBase, l.HoldNovelty = c.N, c.M",
		"if l.HoldNovelty == 0 {\n\t\t\tl.HoldNovelty = c.M\n\t\t}\n\t\tl.HoldBase = c.N"},
	{"derive-task", "the task not reported", "key.go",
		"l.Task = c.Set[0]",
		"_ = c.Set[0]"},
	{"derive-by-owner", "a passkey's narrowing not reported", "key.go",
		"v.ByOwner = true\n",
		"\n"},
	{"narrowers", "no narrowing passkey listed", "key.go",
		"v.Narrowers = append(v.Narrowers, p)",
		"_ = p"},
	{"narrowers-mid", "a narrowing short of the tip not listed", "key.go",
		"v.ByOwner = false\n",
		"v.ByOwner = false\n\t\tv.Narrowers = nil\n"},
	{"within-verbs", "a renewal with wider verbs", "key.go",
		"{{l.Verbs, b.Verbs}, {l.Content, b.Content}, {l.Labels, b.Labels}}",
		"{{l.Content, b.Content}, {l.Labels, b.Labels}}"},
	{"within-content", "a renewal with a wider content set", "key.go",
		"{{l.Verbs, b.Verbs}, {l.Content, b.Content}, {l.Labels, b.Labels}}",
		"{{l.Verbs, b.Verbs}, {l.Labels, b.Labels}}"},
	{"within-labels", "a renewal with a wider labels set", "key.go",
		"{{l.Verbs, b.Verbs}, {l.Content, b.Content}, {l.Labels, b.Labels}}",
		"{{l.Verbs, b.Verbs}, {l.Content, b.Content}}"},
	{"within-arg", "an arg bound the renewal drops", "key.go",
		"if !ok { // a bare bound is a limit too: the arg may not come from the planner (KEY-2)\n\t\t\treturn false",
		"if !ok {\n\t\t\tcontinue"},
	{"within-arg-oneof", "a renewal with a wider arg set", "key.go",
		"(o.OneOf != nil && (a.OneOf == nil || !subset(a.OneOf, o.OneOf))) ||",
		"false ||"},
	{"within-arg-min", "a renewal with a lower arg min", "key.go",
		"(o.Min != nil && (a.Min == nil || *a.Min < *o.Min))",
		"false"},
	{"within-arg-max", "a renewal with a higher arg max", "key.go",
		"(o.Max != nil && (a.Max == nil || *a.Max > *o.Max))",
		"false"},
	{"within-cap", "a cap the renewal drops or raises", "key.go",
		"if !slices.ContainsFunc(l.Caps, func(c Cap) bool { return c.Kind == o.Kind && c.N <= o.N }) {",
		"if !slices.ContainsFunc(l.Caps, func(c Cap) bool { return c.Kind == o.Kind && c.N <= o.N }) && false {"},
	{"within-cap-edge", "a cap the renewal raises by one", "key.go",
		"c.Kind == o.Kind && c.N <= o.N })",
		"c.Kind == o.Kind && c.N <= o.N+1 })"},
	{"within-task", "a task caveat the renewal drops", "key.go",
		"(b.Task == \"\" || l.Task == b.Task) &&",
		"true &&"},
	{"within-hold-base", "a renewal with a shorter base hold", "key.go",
		" && l.HoldBase >= b.HoldBase",
		""},
	{"within-hold-novelty", "a renewal with a shorter novelty hold", "key.go",
		" && l.HoldNovelty >= b.HoldNovelty",
		""},
	{"renew-fresh", "a first link charged to a fresh budget, not the clerk's account", "key.go",
		"scope = account(prev, l.Holder)",
		"scope = id"},
	{"renew-shared", "a first link to another holder charged to the same account", "key.go",
		"h.Write(root[:])\n\th.Write(holder)",
		"h.Write(root[:])"},
	{"no-view", "a check with no revocation view", "authorize.go",
		"if c.Changes == nil {\n\t\treturn refuse(RMalformed, \"no revocation view\")\n\t}",
		"if c.Changes == nil {\n\t\tc.Changes = &Changes{}\n\t}"},
	{"stopped", "a step while stop is in force", "authorize.go",
		"if c.Changes.Stopped {",
		"if false {"},
	{"revoked-root", "a revoked root", "authorize.go",
		"if c.Changes.Revoked[id] {",
		"if c.Changes.Revoked[id] && id != v.IDs[0] {"},
	{"revoked-mid", "a revoked link short of the tip", "authorize.go",
		"if c.Changes.Revoked[id] {",
		"if c.Changes.Revoked[id] && (id == v.IDs[0] || id == v.ID()) {"},
	{"revoked-tip", "a revoked tip", "authorize.go",
		"if c.Changes.Revoked[id] {",
		"if c.Changes.Revoked[id] && (id != v.ID() || len(v.IDs) == 1) {"},
	{"paused", "a paused prefix", "authorize.go",
		"if c.Changes.Paused[id] {",
		"if false {"},
	{"expired", "an expired key", "authorize.go",
		"l.NotAfter != nil && c.Now >= *l.NotAfter {",
		"false {"},
	{"expiry-edge", "a key at its expiry", "authorize.go",
		"c.Now >= *l.NotAfter {",
		"c.Now > *l.NotAfter {"},
	{"clerk", "a step on another clerk", "authorize.go",
		"if s.Clerk != l.Clerk {",
		"if false {"},
	{"step-task", "a step for another task than the key's", "authorize.go",
		"if r := v.task(s.Task); r != nil {",
		"if r := v.task(l.Task); r != nil {"},
	{"step-verb", "a verb outside the root or a verbs caveat", "authorize.go",
		"if !in(l.Verbs, string(s.Verb)) {",
		"if false {"},
	{"arg-count", "a step with an extra argument", "verbs.go",
		"if len(s.Args) != len(want) {",
		"if len(s.Args) < len(want) {"},
	{"arg-missing", "a step missing a declared argument", "verbs.go",
		"if a, ok := s.Args[n]; !ok || a.Value == \"\" {",
		"if a, ok := s.Args[n]; ok && a.Value == \"\" {"},
	{"arg-empty", "a declared argument with no value", "verbs.go",
		"if a, ok := s.Args[n]; !ok || a.Value == \"\" {",
		"if _, ok := s.Args[n]; !ok {"},
	{"content", "content outside a content caveat", "authorize.go",
		"if l.Content != nil && !in(l.Content, s.Content) {",
		"if false {"},
	{"labels", "labels outside a labels caveat", "authorize.go",
		"if !in(l.Labels, x) {",
		"if false {"},
	{"labels-all", "a label outside it after the first", "authorize.go",
		"for _, x := range s.Labels {",
		"for _, x := range s.Labels[:min(1, len(s.Labels))] {"},
	{"arg-present", "a bounded argument absent", "authorize.go",
		"if !ok || a.Source == SrcPlanner || (a.Source != SrcOwner && a.Source != SrcClerk) {",
		"if ok && (a.Source == SrcPlanner || (a.Source != SrcOwner && a.Source != SrcClerk)) {"},
	{"arg-planner", "a bounded argument from the planner", "authorize.go",
		"if !ok || a.Source == SrcPlanner || (a.Source != SrcOwner && a.Source != SrcClerk) {",
		"if !ok || (a.Source != SrcOwner && a.Source != SrcClerk && a.Source != SrcPlanner) {"},
	{"arg-source", "a bounded argument from no named source", "authorize.go",
		"if !ok || a.Source == SrcPlanner || (a.Source != SrcOwner && a.Source != SrcClerk) {",
		"if !ok || a.Source == SrcPlanner || (a.Source != SrcOwner && a.Source != SrcClerk && a.Source != \"\") {"},
	{"arg-oneof", "a bounded argument outside its set", "authorize.go",
		"if b.OneOf != nil && !in(b.OneOf, a.Value) {",
		"if false {"},
	{"arg-parse", "a range-bounded argument that is no number", "authorize.go",
		"if err != nil || (b.Min",
		"if (err != nil && false) || (b.Min"},
	{"arg-min", "a bounded argument below its min", "authorize.go",
		"(b.Min != nil && n < *b.Min)",
		"false"},
	{"arg-min-edge", "a bounded argument one below its min", "authorize.go",
		"(b.Min != nil && n < *b.Min)",
		"(b.Min != nil && n < *b.Min-1)"},
	{"arg-max", "a bounded argument above its max", "authorize.go",
		"(b.Max != nil && n > *b.Max)",
		"false"},
	{"arg-max-edge", "a bounded argument one above its max", "authorize.go",
		"(b.Max != nil && n > *b.Max)",
		"(b.Max != nil && n > *b.Max+1)"},
	{"amount-neg", "a step with a negative amount", "authorize.go",
		"if s.Amount < 0 {",
		"if false {"},
	{"no-ledger", "a capped key checked with no ledger", "authorize.go",
		"if len(v.Limits.Caps) > 0 && c.Ledger == nil {\n\t\treturn refuse(RMalformed, \"no ledger\")\n\t}",
		"if c.Ledger == nil {\n\t\treturn nil\n\t}"},
	{"spend-rate", "Spend checking rate and use caps too (stricter)", "authorize.go",
		"return v.caps(Step{Task: task, Amount: amount}, c, true)",
		"return v.caps(Step{Task: task, Amount: amount}, c, false)"},
	{"cap-scope", "a cap counting uses of every scope (stricter)", "authorize.go",
		"for _, u := range c.Ledger.Uses(cp.Scope) {",
		"for _, u := range func() (us []Use) {\n\t\t\tfor _, sc := range v.Scopes() {\n\t\t\t\tus = append(us, c.Ledger.Uses(sc)...)\n\t\t\t}\n\t\t\treturn us\n\t\t}() {"},
	{"spend-task-match", "a per-task cap counting every task (stricter)", "authorize.go",
		"if u.Task == s.Task && ok {",
		"if ok {"},
	{"spend-task", "a step over the per-task cap", "authorize.go",
		"if !ok || sum > cp.N {\n\t\t\t\treturn refuse(RSpendTask",
		"if false {\n\t\t\t\treturn refuse(RSpendTask"},
	{"spend-task-edge", "a step one over the per-task cap", "authorize.go",
		"if !ok || sum > cp.N {\n\t\t\t\treturn refuse(RSpendTask",
		"if !ok || sum > cp.N+1 {\n\t\t\t\treturn refuse(RSpendTask"},
	{"spend-day-window", "a daily cap counting old uses (stricter)", "authorize.go",
		"if u.At > c.Now-DayMS && ok {",
		"if ok {"},
	{"spend-day-window-edge", "a daily cap counting a use exactly a day old", "authorize.go",
		"if u.At > c.Now-DayMS && ok {",
		"if u.At >= c.Now-DayMS && ok {"},
	{"spend-day", "a step over the daily spend cap", "authorize.go",
		"if !ok || sum > cp.N {\n\t\t\t\treturn refuse(RSpendDay",
		"if false {\n\t\t\t\treturn refuse(RSpendDay"},
	{"spend-day-edge", "a step one over the daily spend cap", "authorize.go",
		"if !ok || sum > cp.N {\n\t\t\t\treturn refuse(RSpendDay",
		"if !ok || sum > cp.N+1 {\n\t\t\t\treturn refuse(RSpendDay"},
	{"rate-day-window", "a daily rate counting old uses (stricter)", "authorize.go",
		"case KRateDay:\n\t\t\t\tif u.At > c.Now-DayMS {",
		"case KRateDay:\n\t\t\t\tif true {"},
	{"rate-day-window-edge", "a daily rate counting a use exactly a day old", "authorize.go",
		"case KRateDay:\n\t\t\t\tif u.At > c.Now-DayMS {",
		"case KRateDay:\n\t\t\t\tif u.At >= c.Now-DayMS {"},
	{"rate-day", "a step over the daily rate", "authorize.go",
		"case KRateDay, KRateRecipient:\n\t\t\tif n+1 > cp.N {",
		"case KRateDay, KRateRecipient:\n\t\t\tif n+1 > cp.N && cp.Kind != KRateDay {"},
	{"rate-day-edge", "a step one over the daily rate", "authorize.go",
		"case KRateDay, KRateRecipient:\n\t\t\tif n+1 > cp.N {",
		"case KRateDay, KRateRecipient:\n\t\t\tif (cp.Kind == KRateDay && n > cp.N) || (cp.Kind != KRateDay && n+1 > cp.N) {"},
	{"rate-recipient-window", "a per-recipient rate counting old uses (stricter)", "authorize.go",
		"if u.At > c.Now-DayMS && u.Recipient == s.Recipient {",
		"if u.Recipient == s.Recipient {"},
	{"rate-recipient-window-edge", "a per-recipient rate counting a use exactly a day old", "authorize.go",
		"if u.At > c.Now-DayMS && u.Recipient == s.Recipient {",
		"if u.At >= c.Now-DayMS && u.Recipient == s.Recipient {"},
	{"rate-recipient-match", "a per-recipient rate counting every recipient (stricter)", "authorize.go",
		"if u.At > c.Now-DayMS && u.Recipient == s.Recipient {",
		"if u.At > c.Now-DayMS {"},
	{"rate-recipient", "a step over the per-recipient rate", "authorize.go",
		"case KRateDay, KRateRecipient:\n\t\t\tif n+1 > cp.N {",
		"case KRateDay, KRateRecipient:\n\t\t\tif n+1 > cp.N && cp.Kind != KRateRecipient {"},
	{"rate-recipient-edge", "a step one over the per-recipient rate", "authorize.go",
		"case KRateDay, KRateRecipient:\n\t\t\tif n+1 > cp.N {",
		"case KRateDay, KRateRecipient:\n\t\t\tif (cp.Kind == KRateRecipient && n > cp.N) || (cp.Kind != KRateRecipient && n+1 > cp.N) {"},
	{"uses-all-time", "a uses cap counting only the last day", "authorize.go",
		"case KUses:\n\t\t\t\tn++",
		"case KUses:\n\t\t\t\tif u.At > c.Now-DayMS {\n\t\t\t\t\tn++\n\t\t\t\t}"},
	{"uses", "a step over the uses cap", "authorize.go",
		"case KUses:\n\t\t\tif n+1 > cp.N {",
		"case KUses:\n\t\t\tif false {"},
	{"uses-edge", "a step one over the uses cap", "authorize.go",
		"case KUses:\n\t\t\tif n+1 > cp.N {",
		"case KUses:\n\t\t\tif n > cp.N {"},
	{"spend-for-task", "a metered call for another task than the key's", "authorize.go",
		"if r := v.task(task); r != nil {",
		"if r := v.task(v.Limits.Task); r != nil {"},
	{"spend-amount-neg", "a negative metered amount", "authorize.go",
		"if amount < 0 {",
		"if false {"},
	{"spend-capped", "a metered call on a key with no spend cap", "authorize.go",
		"if !capped {",
		"if false {"},
}

func TestPredicateReach(t *testing.T) {
	if os.Getenv("KEYDIFF_REACH") == "" || os.Getenv("KEYCHECK") == "" {
		t.Skip("set KEYDIFF_REACH and KEYCHECK to run the predicate-reach check")
	}
	lib, err := filepath.Abs(filepath.Join("..", "..", "kernel", "key"))
	if err != nil {
		t.Fatal(err)
	}
	cases := os.Getenv("KEYDIFF_REACH_CASES")
	if cases == "" {
		cases = "100000"
	}
	// The baseline check must itself catch a disagreement at the very end of
	// the range: each seed asks keycheck two questions, and the fake flips
	// the answer to the last.
	t.Run("baseline-catches-plant", func(t *testing.T) {
		n, err := strconv.Atoi(cases)
		if err != nil {
			t.Fatal(err)
		}
		at := 2 * n
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		out, err := sweep("", cases, "KEYCHECK="+self, "KEYDIFF_PLANT_REAL="+os.Getenv("KEYCHECK"), "KEYDIFF_PLANT_AT="+strconv.Itoa(at))
		if err == nil || !strings.Contains(string(out), "cases disagree") {
			t.Fatalf("a disagreement planted at keycheck's answer %d went unseen:\n%s", at, tail(string(out), 20))
		}
	})
	if out, err := sweep("", cases); err != nil {
		t.Fatalf("the unmutated library fails the sweep over the reach range, so no kill can be trusted:\n%s", tail(string(out), 20))
	}
	slots := make(chan struct{}, runtime.NumCPU())
	for _, m := range libMutants {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			slots <- struct{}{}
			defer func() { <-slots }()
			path := filepath.Join(lib, m.file)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(src), m.old); n != 1 {
				t.Fatalf("%s: the text to replace occurs %d times in %s; update the mutant", m.why, n, m.file)
			}
			dir := t.TempDir()
			mutated := filepath.Join(dir, m.file)
			if err := os.WriteFile(mutated, []byte(strings.Replace(string(src), m.old, m.new, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]map[string]string{"Replace": {path: mutated}})
			ov := filepath.Join(dir, "overlay.json")
			if err := os.WriteFile(ov, overlay, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := sweep(ov, cases)
			switch {
			case err == nil:
				t.Errorf("survived: no seed separates the library from keycheck once it lets through %s", m.why)
			case !strings.Contains(string(out), "cases disagree"):
				t.Errorf("failed without a disagreement (%s):\n%s", m.why, tail(string(out), 20))
			default:
				_, first, _ := strings.Cut(string(out), "seed ")
				first, _, _ = strings.Cut(first, "\n")
				t.Logf("killed at seed %s", first)
			}
		})
	}
}

// sweep runs TestKeyDiff over seeds 0..cases, stopping at the first
// disagreement, with the library replaced as overlay ov says ("" for none)
// and env added to the environment.
func sweep(ov, cases string, env ...string) ([]byte, error) {
	args := []string{"test"}
	if ov != "" {
		args = append(args, "-overlay", ov)
	}
	cmd := exec.Command("go", append(args, "-count=1", "-run", "^TestKeyDiff$", ".")...)
	cmd.Env = append(append(os.Environ(), "KEYDIFF_STOP=1", "KEYDIFF_REACH=", "KEYDIFF_FROM=0", "KEYDIFF_CASES="+cases), env...)
	return cmd.CombinedOutput()
}

// TestMain runs this binary as the planted fake keycheck when it is started
// with no arguments, as keycheck is, and KEYDIFF_PLANT_REAL names the real one.
// go test always passes -test flags, so the sweep's own binary never is.
func TestMain(m *testing.M) {
	if real := os.Getenv("KEYDIFF_PLANT_REAL"); real != "" && len(os.Args) == 1 {
		at, _ := strconv.Atoi(os.Getenv("KEYDIFF_PLANT_AT"))
		if err := plant(real, at); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// plant relays stdin to the real keycheck and its answers back, with the
// verdict and the within flag of answer at (counted from 1) flipped.
func plant(real string, at int) error {
	cmd := exec.Command(real)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	r, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if n == at {
			var v map[string]any
			if err := json.Unmarshal(line, &v); err != nil {
				return err
			}
			valid, _ := v["valid"].(bool)
			within, _ := v["within"].(bool)
			v["valid"], v["within"] = !valid, !within
			if line, err = json.Marshal(v); err != nil {
				return err
			}
		}
		w.Write(line)
		w.WriteByte('\n')
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return cmd.Wait()
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
