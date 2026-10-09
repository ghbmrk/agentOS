# W3-forget-b1-7: Text the owner a held restore, and take their answer

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md), after W3-forget-b1-4 (briefs/W3-forget-b1-4.md); SPEC CAP-3, A8, CH-12.

**Requirement IDs:** security C3's "a failed check keeps the restore pending and tells the owner" (today agentosd logs and exits, so the owner is never told: #409 UX U2, release); CAP-3 (only the owner's authenticated channel answers); A8 and CH-12 for the texts.

**Design.** When `forget-log.json.pending` exists, agentosd does not exit. It runs a held mode instead, modelled on setup mode (setup.go). Held mode opens nothing on the restored tree (no recall, machines, learning or owner-channel state) and serves only `owner.sock`, with the same peer checks as the daemon's. On it:
- the modem bridge's ops (`modemlink.Link.Ops`) under `-modem-bridge`, and "message" unless the box is bridge-only, as in the daemon.

The owner's number comes from `-owner` or from setup's finished record. With neither, nothing can text the owner, and agentosd exits as today.

Held mode's texts:
1. It sends one text at start. If the hold has a question (W3-forget-b1-4), the text is the question, or the wrong-answer text when the question is already closed. Otherwise it is the marker's PendingNotice, kept to GSM-7 within three segments, with a fixed text as fallback. The send retries until the bridge reports the line up.
2. It answers each owner reply in turn:
   - The reply goes through `answerHeld`, or gets the notice when there is no question.
   - Replies come only from the link's inbox (the owner line, sender checked) or from "message" with `From` equal to the owner. Anything else is dropped unanswered (#436 L3 point 4).
   - One reply is handled at a time (#436 L3 point 5).
   - A reply longer than 64 bytes is no choice (#436 L3 point 8).
   - STOP, STATUS and any other word get the held text back. The agent is not running, so there is nothing else to say.
3. On release it sends the confirmation, which returns once the bridge has taken it, and then stops serving. agentosd checks the marker again and starts as normal with a new link.

**Text changes (#436 UX, release):**
- The unanchored header becomes "Restore on hold: this PC can't check your forget list." (point 1).
- When there is no newer backup, the wrong-answer text adds "If you picked by mistake, restore this backup again to answer again." (point 2).
- Point 3 (a "since this backup" wording for the missing case) went to Mark and is not in this package.

**CH-12 recurring-kind check (#409 UX U6, release):** a table test over every text held mode can send. For each text it asserts:
- the text is GSM-7 and at most three segments;
- every step the text names (a reply letter, a control word, "restore … again", "restore … instead", "update") is one that can act in that state;
- every text that expects a reply lists the valid replies.

The check is recorded in reviews/ux/README.md under "Checks that replaced findings".

**Needs:** W3-forget-b1 (#409) and W3-forget-b1-4 (#436), both merged. W3-forget-b1-6 and then W3-forget-b1-5 wait on this package.

**Gate:** tier A (cmd/agentosd, recovery state). Needs L3, the UX lens on the texts, and Security 4a (who may answer, and what a held box opens).

**Scope:** `broker/cmd/agentosd/` (main.go, restoreconfirm.go, a new held.go and their tests, ASSUMPTIONS.md), reviews/ux/README.md, BOARD.md, LATER.md; `broker/daemon/arc2_test.go` for agentosd's ARC-2 import list (bridgeproto, modem), added when CI found it; `broker/sockets/` (sockets.go, sockets_test.go) so a handler that ends its server still answers, added for #487 L3 point 1.

**Estimate:** under 120k tokens, strongest model (tier A).
