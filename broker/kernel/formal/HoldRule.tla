----------------------------- MODULE HoldRule -----------------------------
(* The hold rule of SPEC KEY-8 and KRN-4, as kernel.Next implements it: one *)
(* plan step under a key with a hold caveat, from submission to dispatch.   *)
(*                                                                          *)
(* An irreversible step under a key whose windows are not both zero is      *)
(* held. Its novelty is fixed when it is held: novel when no step of the    *)
(* same shape has completed under the key's root. It dispatches once its    *)
(* window has passed: the novelty window when novel, the base one when not. *)
(* The owner can stop it at any point before dispatch (UNDO, STOP or a      *)
(* revoke). A step of the same shape may complete under the same root while *)
(* this one is held; that must not shorten this one's hold.                 *)
(*                                                                          *)
(* The kernel runs Next on every tick, so a step dispatches at the first    *)
(* tick its rule allows. vectors.py, beside this file, reads the earliest   *)
(* dispatch time for each scenario from TLC's state dump into               *)
(* broker/kernel/testdata/formal/hold.json, and formal_hold_test.go replays *)
(* each scenario through the real kernel.                                   *)
EXTENDS Integers

CONSTANTS MaxNow

Verbs == {"organize", "send"}
Irreversible(v) == v = "send"   \* key.ClassOf: organize is reversible
\* A key's hold caveat, <<base, novelty>> in hours (key.LimitHold).
Holds == {<<0, 0>>, <<0, 2>>, <<1, 1>>, <<1, 3>>, <<2, 2>>}

Window(h, novel) == IF novel THEN h[2] ELSE h[1]

VARIABLES
  hold,      \* the key's hold caveat
  verb,
  seen,      \* a step of this shape completed under the root before this one was held
  phase,     \* "queued", "held", "sent" or "cancelled"
  heldAt, novel, sentAt,
  midHold,   \* a step of this shape completed under the root while this one was held
  now
vars == <<hold, verb, seen, phase, heldAt, novel, sentAt, midHold, now>>

TypeOK ==
  /\ hold \in Holds /\ verb \in Verbs /\ seen \in BOOLEAN /\ midHold \in BOOLEAN
  /\ phase \in {"queued", "held", "sent", "cancelled"}
  /\ heldAt \in -1..MaxNow /\ sentAt \in -1..MaxNow /\ novel \in BOOLEAN
  /\ now \in 0..MaxNow

Init ==
  /\ hold \in Holds /\ verb \in Verbs /\ seen \in BOOLEAN
  /\ phase = "queued" /\ heldAt = -1 /\ novel = FALSE /\ sentAt = -1
  /\ midHold = FALSE /\ now = 0

Due == heldAt + Window(hold, novel)

\* kernel.Next for the step.
Kernel ==
  \/ /\ phase = "queued"
     /\ IF Irreversible(verb) /\ (hold[1] > 0 \/ hold[2] > 0)
          THEN /\ phase' = "held" /\ heldAt' = now /\ novel' = ~seen
               /\ UNCHANGED sentAt
          ELSE /\ phase' = "sent" /\ sentAt' = now
               /\ UNCHANGED <<heldAt, novel>>
     /\ UNCHANGED <<hold, verb, seen, midHold, now>>
  \/ /\ phase = "held" /\ now >= Due
     /\ phase' = "sent" /\ sentAt' = now
     /\ UNCHANGED <<hold, verb, seen, heldAt, novel, midHold, now>>

Tick == now < MaxNow /\ now' = now + 1
        /\ UNCHANGED <<hold, verb, seen, phase, heldAt, novel, sentAt, midHold>>

\* Another step of the same shape completes under the same root.
SameShape == phase = "held" /\ ~midHold /\ midHold' = TRUE /\ seen' = TRUE
             /\ UNCHANGED <<hold, verb, phase, heldAt, novel, sentAt, now>>

\* UNDO, STOP or a revoke before dispatch.
Cancel == phase \in {"queued", "held"} /\ phase' = "cancelled"
          /\ UNCHANGED <<hold, verb, seen, heldAt, novel, sentAt, midHold, now>>

Next == Kernel \/ Tick \/ SameShape \/ Cancel

Spec == Init /\ [][Next]_vars

(* ---- invariants --------------------------------------------------------- *)

\* KRN-4/KEY-8: an irreversible step under a non-zero window is held first,
\* and dispatches only once its window has passed.
NoEarlyDispatch ==
  phase = "sent" /\ Irreversible(verb) /\ (hold[1] > 0 \/ hold[2] > 0)
    => heldAt >= 0 /\ sentAt >= Due

\* KEY-8/OWN-9: novelty only lengthens. A novel step waits at least the base
\* window, and novelty is what the root had seen when the step was held.
NoveltyOnlyLengthens ==
  phase \in {"held", "sent"} /\ heldAt >= 0 =>
    /\ Due >= heldAt + hold[1]
    /\ (novel => Due = heldAt + hold[2])

\* A reversible step, or one under a zero window, is never held.
OnlyIrreversibleHeld ==
  heldAt >= 0 => Irreversible(verb) /\ (hold[1] > 0 \/ hold[2] > 0)

\* KEY-8: holds never shorten. Once held, the due time never moves earlier,
\* whatever completes under the root meanwhile.
HoldsNeverShorten == [][phase = "held" => Due' >= Due]_vars

\* KEY-8/KRN-7: a step stopped during its hold never dispatches.
CancelFinal == [][phase = "cancelled" => phase' = "cancelled"]_vars
=============================================================================
