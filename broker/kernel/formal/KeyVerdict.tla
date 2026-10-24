---------------------------- MODULE KeyVerdict ----------------------------
(* The key check of SPEC KEY-1..KEY-7, as broker/kernel/key implements it   *)
(* (Verify, then Verified.Authorize and Limits.Window).                     *)
(*                                                                          *)
(* A key is a root, the passkey's grant (the first link: an expiry and a    *)
(* daily spend cap, KEY-4), then up to MaxLinks further links. Each further *)
(* link adds one caveat and is signed by the key's holder, by a passkey     *)
(* narrowing for that holder (key.Narrow), or by a stranger. The state is   *)
(* one key plus the context a check reads (time, prior uses, a stop, a      *)
(* revocation or a pause), and `verdict` is the check's answer for every    *)
(* step in Steps. Every reachable state is a test vector: vectors.py,       *)
(* beside this file, turns TLC's state dump into                            *)
(* broker/kernel/key/testdata/formal/.                                      *)
(*                                                                          *)
(* Signatures are not bytes here: a link records who signed it. Argument    *)
(* bounds, content and the spend and rate caps are left to the Go reference *)
(* model (broker/kernel/key/refmodel_test.go); `uses` stands for the        *)
(* counted caps, since all of them charge every prefix of a chain alike.    *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS MaxLinks, MaxNow, MaxUsed

Verbs   == {"organize", "unsubscribe"}   \* a reversible and an irreversible verb (VRB-2)
Labels  == {"a", "b"}
Signers == {"holder", "passkey", "stranger"}

\* One caveat. Every field is always present, so TLC compares like with like.
Cav(k, s, n, m) == [k |-> k, s |-> s, n |-> n, m |-> m]
Caveats ==
       {Cav("verbs", s, 0, 0)  : s \in SUBSET Verbs}
  \cup {Cav("labels", s, 0, 0) : s \in SUBSET Labels}
  \cup {Cav("hold", {}, b, w)  : <<b, w>> \in {<<0, 0>>, <<1, 1>>, <<0, 2>>, <<1, 2>>, <<2, 1>>}}
  \cup {Cav("expires", {}, t, 0) : t \in 1..MaxNow}
  \cup {Cav("uses", {}, n, 0)  : n \in 0..MaxUsed}
Links == [sig : Signers, cav : Caveats]

\* Steps: a verb and the flow labels the step's data carries. StepList fixes
\* their order, so a verdict table prints as a short sequence.
StepList == <<[verb |-> "organize", labels |-> {}], [verb |-> "organize", labels |-> {"a"}],
              [verb |-> "organize", labels |-> {"b"}], [verb |-> "organize", labels |-> {"a", "b"}],
              [verb |-> "unsubscribe", labels |-> {}], [verb |-> "unsubscribe", labels |-> {"a"}],
              [verb |-> "unsubscribe", labels |-> {"b"}], [verb |-> "unsubscribe", labels |-> {"a", "b"}]>>
StepIx == 1..Len(StepList)
Steps == {StepList[i] : i \in StepIx}

\* What a check reads besides the key. "revoke" and "pause" name a chain
\* prefix: 0 the root, 1 the grant, 1+i the i-th further link.
Cut == [k : {"none", "stop", "revoke", "pause"}, i : 0..(MaxLinks + 1)]
NoCut == [k |-> "none", i |-> 0]

Codes == {"ok", "invalid", "stopped", "revoked", "paused", "expired", "verb", "labels", "uses"}

None == -1

(* ---- the chain ---------------------------------------------------------- *)

\* The limits a valid chain sets: the conjunction of its links (KEY-3).
\* lset is FALSE until a link sets labels; expiry None means only the grant's.
Init0 == [verbs |-> Verbs, labels |-> Labels, lset |-> FALSE, base |-> 0, nov |-> 0,
          expiry |-> None, uses |-> {}, ok |-> TRUE]

\* Adding one caveat: refused when malformed or when it loosens (KEY-3).
AddCav(l, c) ==
  CASE c.k = "verbs"   -> IF c.s \subseteq l.verbs THEN [l EXCEPT !.verbs = c.s] ELSE [l EXCEPT !.ok = FALSE]
    [] c.k = "labels"  -> IF ~l.lset \/ c.s \subseteq l.labels
                            THEN [l EXCEPT !.labels = c.s, !.lset = TRUE] ELSE [l EXCEPT !.ok = FALSE]
    [] c.k = "hold"    -> IF c.m < c.n \/ c.n < l.base \/ c.m < l.nov
                            THEN [l EXCEPT !.ok = FALSE] ELSE [l EXCEPT !.base = c.n, !.nov = c.m]
    [] c.k = "expires" -> IF l.expiry # None /\ c.n > l.expiry
                            THEN [l EXCEPT !.ok = FALSE] ELSE [l EXCEPT !.expiry = c.n]
    [] c.k = "uses"    -> IF \E u \in l.uses : c.n > u
                            THEN [l EXCEPT !.ok = FALSE] ELSE [l EXCEPT !.uses = l.uses \cup {c.n}]

AddLink(l, lk) == IF ~l.ok \/ lk.sig = "stranger" THEN [l EXCEPT !.ok = FALSE] ELSE AddCav(l, lk.cav)

RECURSIVE FoldFrom(_, _, _)
FoldFrom(l, ch, i) == IF i > Len(ch) THEN l ELSE FoldFrom(AddLink(l, ch[i]), ch, i + 1)

\* A root its owner did not sign is no key (KEY-1).
Limits(rootOK, ch) == IF rootOK THEN FoldFrom(Init0, ch, 1) ELSE [Init0 EXCEPT !.ok = FALSE]

\* The hold before an irreversible step (KEY-8).
Window(l, novel) == IF novel THEN l.nov ELSE l.base

(* ---- the check ---------------------------------------------------------- *)

\* Authorize's order: stop, revocation and pause along the chain, expiry, the
\* verb, the labels, then the counted caps against the uses already charged.
Verdict(rootOK, ch, now, used, cut, s) ==
  LET l == Limits(rootOK, ch) IN
  CASE ~l.ok                                        -> "invalid"
    [] cut.k = "stop"                               -> "stopped"
    [] cut.k = "revoke" /\ cut.i <= Len(ch) + 1     -> "revoked"
    [] cut.k = "pause"  /\ cut.i <= Len(ch) + 1     -> "paused"
    [] l.expiry # None /\ now >= l.expiry           -> "expired"
    [] s.verb \notin l.verbs                        -> "verb"
    [] l.lset /\ ~(s.labels \subseteq l.labels) -> "labels"
    [] \E u \in l.uses : used + 1 > u               -> "uses"
    [] OTHER                                        -> "ok"

Table(rootOK, ch, now, used, cut) == [i \in StepIx |-> Verdict(rootOK, ch, now, used, cut, StepList[i])]

(* ---- the state machine -------------------------------------------------- *)

\* The windows a check of a valid key would hold an irreversible step for,
\* <<base, novelty>>; <<-1, -1>> for a key that does not check out.
Windows(rootOK, ch) == LET l == Limits(rootOK, ch) IN
  IF l.ok THEN <<Window(l, FALSE), Window(l, TRUE)>> ELSE <<-1, -1>>

VARIABLES rootOK, chain, now, used, cut, verdict, window
vars == <<rootOK, chain, now, used, cut, verdict, window>>

TypeOK ==
  /\ rootOK \in BOOLEAN
  /\ chain \in Seq(Links) /\ Len(chain) <= MaxLinks
  /\ now \in 0..MaxNow /\ used \in 0..MaxUsed
  /\ cut \in Cut
  /\ verdict \in [StepIx -> Codes]
  /\ Steps = [verb : Verbs, labels : SUBSET Labels]

Init ==
  /\ rootOK \in BOOLEAN
  /\ chain = <<>> /\ now = 0 /\ used = 0 /\ cut = NoCut
  /\ verdict = Table(rootOK, chain, now, used, cut)
  /\ window = Windows(rootOK, chain)

\* Anyone may append a link to a key that checks out; the check decides
\* whether the result is a key. Appending to a broken key gains nothing.
Extend == \E lk \in Links :
  /\ Len(chain) < MaxLinks /\ Limits(rootOK, chain).ok
  /\ chain' = Append(chain, lk)
  /\ UNCHANGED <<rootOK, now, used, cut>>

\* The context moves only under a key that checks out: a broken one is
\* "invalid" in every context, so varying it there adds states and no test.
Live == Limits(rootOK, chain).ok

Tick   == Live /\ now < MaxNow /\ now' = now + 1 /\ UNCHANGED <<rootOK, chain, used, cut>>
Charge == Live /\ used < MaxUsed /\ used' = used + 1 /\ UNCHANGED <<rootOK, chain, now, cut>>

\* STOP, a revoke or a pause of any prefix. STOP and a pause can be lifted;
\* a revocation cannot (KEY-7), so it has no inverse here.
Narrow == Live /\ cut = NoCut /\ \E c \in Cut :
  /\ c.k # "none" /\ c.i <= Len(chain) + 1 /\ (c.k = "stop" => c.i = 0)
  /\ cut' = c /\ UNCHANGED <<rootOK, chain, now, used>>
Lift == cut.k \in {"stop", "pause"} /\ cut' = NoCut /\ UNCHANGED <<rootOK, chain, now, used>>

Next ==
  /\ (Extend \/ Tick \/ Charge \/ Narrow \/ Lift)
  /\ verdict' = Table(rootOK', chain', now', used', cut')
  /\ window' = Windows(rootOK', chain')

Spec == Init /\ [][Next]_vars

(* ---- invariants --------------------------------------------------------- *)

Parent == SubSeq(chain, 1, Len(chain) - 1)
Admits(ch, s) == Verdict(rootOK, ch, now, used, cut, s) = "ok"

\* KEY-3/KEY-4: no link widens authority, whoever signs it, the passkey
\* included. Only a new root or grant, which only a passkey can sign, adds
\* power; a root the owner did not sign admits nothing.
NoWidening ==
  /\ Len(chain) > 0 => \A s \in Steps : Admits(chain, s) => Admits(Parent, s)
  /\ ~rootOK => \A i \in StepIx : verdict[i] = "invalid"
  /\ \A j \in 1..Len(chain) : chain[j].sig = "stranger" => \A i \in StepIx : verdict[i] = "invalid"

\* KEY-3/KEY-8: holds never shorten. Along a chain each window is at least the
\* parent's, and novelty only lengthens a window.
HoldsNeverShorten ==
  LET l == Limits(rootOK, chain) IN
  l.ok =>
    /\ Window(l, TRUE) >= Window(l, FALSE)
    /\ Len(chain) > 0 =>
         \A nv \in BOOLEAN : Window(l, nv) >= Window(Limits(rootOK, Parent), nv)

\* PLN-3/KEY-2: labels only accumulate. A chain's allowed labels only shrink,
\* and a step that carries more labels is never admitted where fewer were not.
LabelsOnlyAccumulate ==
  /\ LET l == Limits(rootOK, chain) IN
       (l.ok /\ Len(chain) > 0 /\ Limits(rootOK, Parent).lset)
         => l.lset /\ l.labels \subseteq Limits(rootOK, Parent).labels
  /\ \A i, j \in StepIx : (StepList[i].verb = StepList[j].verb /\ StepList[i].labels \subseteq StepList[j].labels
                            /\ verdict[j] = "ok") => verdict[i] = "ok"

\* KEY-6/KEY-7/KRN-7: a stop, a revocation or a pause of any prefix, and an
\* expiry, admit nothing, for every key derived after them as well.
NarrowingWins ==
  LET x == Limits(rootOK, chain).expiry IN
  (cut.k # "none" \/ (x # None /\ now >= x))
    => \A i \in StepIx : verdict[i] # "ok"

\* verdict is always the check of the current state (the vectors rely on it).
VerdictCurrent == verdict = Table(rootOK, chain, now, used, cut) /\ window = Windows(rootOK, chain)

\* KEY-7 as a step property: a revocation is never lifted.
RevocationFinal == [][cut.k = "revoke" => cut' = cut]_vars
=============================================================================
