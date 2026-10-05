# ADP-11 amendment: calendar acceptance

Mark decided (project chat, 2026-10-04 23:55): "yes on calendar if user is the one sending the affirmation (“yes that works”)". The arbitrator recorded the rule (PR #13, after D2) and asked the potency loop to spec it. This PR is that spec diff. It is built once a calendar adapter exists.

## What changes

An earned ADP-11 reply may name a date or time without a prompt only when it accepts a slot. The broker checks four things deterministically:

1. The slot is the counterpart's own, taken from the latest inbound message.
2. The slot is free on the owner's calendar, checked when the reply is queued and again just before it sends.
3. The counterpart is a known contact.
4. The reply carries nothing else that would trigger the commitment filter.

The alert and `UNDO` stay as they are.

## Open points, decided here

No lens gets worse under either decision, so both were decided on the recommendation (AUTO-DECIDE).

| Point | Decision | Potency | Security | UX |
|---|---|---|---|---|
| Are "confirm" and "accept" exempt when they accept only that slot? | **No.** The six phrases still prompt. The composer accepts in plain words ("yes, that works"), which is the wording Mark gave. | 0. The composer can always pick wording that isn't one of the phrases. | 0. An exemption would need a check of what the phrase refers to, which the broker can't do without inference (ARC-2). | 0 |
| Does the box book a hold? | **A tentative private hold, only with a calendar-write grant.** The hold is journaled as its own intent and removed by the reply's `UNDO` or when the reply is withheld. Without the grant, no hold is placed. | + Prevents double-booking between the reply and the counterpart's invite. | 0. The hold is an owner-only event with no attendees, and it is reversible. | + |

## Revisions after L3 review

- **Known contacts.** The sender must pass authentication (aligned DMARC for mail), and every recipient must be in the owner's contacts.
- **Hold.** The hold is a draft-class operation with an enforced shape: no attendees, no notifications, private, and a fixed title. The send-time free check ignores the broker's own hold, and tentative events count as busy. The hold is removed when an invite arrives, after 48 h, or before the slot starts, whichever comes first, and the digest lists holds still waiting.
- **Probing bound.** Acceptances are limited to one per thread per day and 3 per day in total, with holds counted.
- **Alert.** The alert uses a fixed template. A time with no stated zone takes the zone of the message's `Date` header.

## Residual risk

- A slot's meaning can be misread when a message names a time without a date, or in a time zone the owner isn't in. Both cases fail to resolve and so prompt.
- A counterpart can propose a slot that is free for the owner but which the owner doesn't want. The alert and the undo window cover this, as they do every other ADP-11 reply.
