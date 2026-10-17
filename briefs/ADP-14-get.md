# ADP-14-get: Hold credentialed GETs that match a state-changing link

**Owner:** primary lane. **Issue:** #1142.
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Parent:** [CRED-4b](CRED-4b.md) (part 2 work; part 1 is the gate in `broker/browser`).
**Requirements:** ADP-14, CRED-4
**Acceptance:** A5, A13.
**Acceptance tests:** `TestStateChangingNavigateIsHeldNotSent`, `TestHeldLinkIsReleasedOnlyAsApproved`, `TestClickOnAStateChangingLinkIsHeld`, `TestClickOnAnUnseenRefIsRefused`, `TestHeldClickReleaseRechecksThePage`, `TestOrdinaryLinksStillPass`, `TestStateLinkPatterns`, `TestStateLinksFromConfig` (all in `broker/browser/statelink_test.go`).

## Finding

ADP-14 gates submits by method: a state-changing request is any method but GET, HEAD or OPTIONS. Its own definition of a submit, though, includes "a button, link, or form whose activation can change state at the site", and many sites change state on a GET: an unsubscribe or confirm link in a mail, an RSVP, a one-click cancel. A credentialed `navigate` to `https://site/unsubscribe?token=…`, or a `click` on a link to it, is fetched with the owner's session and the account is unsubscribed with no approval. That is the failure path.

## Scope and intended change

`broker/browser/**` and this brief only. `tools/ASSUMPTIONS.md` is out of scope (open PRs #2164 and #1992 hold it); the package's assumptions are recorded below and in `broker/browser/ASSUMPTIONS.md`.

1. **Pattern.** A URL is a state-changing link when a word of its path or query (keys and values, split on punctuation and camelCase) is an action word (unsubscribe, opt-out, confirm, verify, activate, cancel, delete, remove, approve, accept, decline, reject, revoke, logout, rsvp, …), or a query key names a one-time or anti-forgery token (`token`, `nonce`, `csrf`, `sig`, …). A recipe adds its own patterns through `Config.StateLinks` (path prefixes on the declared origins); it never removes the defaults.
2. **Hold, not send.** In the credentialed gate, a `navigate` whose URL matches is never forwarded to the driver. `Do` returns `error: "held"` with a hold id, and the gate keeps the held request (origin, method GET, exact URL) for the broker's approval path, like ADP-14's unknown-submit approval for a POST.
3. **Links by ref.** The gate reads every snapshot the driver returns (before filtering) and records, per ref, a link's target URL and accessible name; an element nested in a link (an image, an icon) takes the enclosing link's target and adds its name, since a click on it follows the link. A `click` on a link ref whose target or name matches is held the same way, bound to the resolved target URL. A `click` or `download` on a ref not in the last snapshot the gate saw is refused (`unknown_ref`), so the gate always knows what a link points at. `type` and `select` follow no link and are not checked (AS5).
4. **Release.** `Gate.Release(ctx, id, url)` is broker-side only (not a protocol verb): it forwards exactly the held request once, and only if `url` equals the held URL; any other value voids nothing and sends nothing. The agent cannot reach it.
5. `broker/browser/ASSUMPTIONS.md` gains G9 and a known-limit entry (K15) for what a gate in front of the driver cannot see (below).

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A credentialed `navigate` to a synthetic `https://shop.example.test/unsubscribe?token=…` is held: the driver receives nothing, the result is `held` with an id (A5/A13 shape: held for the owner like a POST, never sent unasked).
2. `Release` with the held URL forwards exactly that request once; a second release, an unknown id, or a different URL forwards nothing. A held click is released only if a fresh snapshot shows the ref still linking to the held URL; otherwise the hold is void.
3. A `click` on a snapshot link whose `/url` is `/email/confirm?t=…` (relative, resolved against the page) or whose name is "Unsubscribe", or on an image inside an unsubscribe link or an "Unsubscribe" child of an ordinary link, is held and not forwarded.
4. A `click` on a ref absent from the last snapshot is refused and not forwarded.
5. Ordinary navigations and link clicks (`/products/kettle`, `/search?q=kettle`, a button, a link whose only nested `/url` belongs to a child) still pass. A search for an action word (`/search?q=cancel+culture`) is held: over-matching fails closed (AS2).
6. Pattern table: positive and negative cases for path words, query keys and values, camelCase, token keys, and recipe prefixes; `Start` refuses a recipe pattern off the declared origins.

Failure path: the GET is fetched and the account is unsubscribed.

Synthetic canaries only. Tests carry `REQ: ADP-14, CRED-4`.

## Assumptions (this package)

- **AS1** Action words are a deny-by-pattern heuristic, not a proof of safety: a GET to a path with no action word can still change state. The boundary for that is part 2's network-level egress gate (SPEC CRED-12 computer-use mode, "Submits are bound at the network"), which also sees redirects and script-initiated GETs. This package narrows the common case (mail-style action links) in front of the driver.
- **AS2** Over-matching fails closed: a search for "cancel" or a page called `/remove-stains-guide` is held for the owner. Recorded as an availability cost, like K12.
- **AS3** The ref map comes from the driver's snapshot, and the driver is untrusted (it renders stranger pages). A driver that lies about a link's target defeats rule 3; the egress gate is the boundary for that too.
- **AS4** The hold store is in memory and per gate; a stopped gate drops its holds, and the owner's approval of a dropped hold sends nothing.
- **AS5** `type` with `submit` or a `select` can make a page issue a GET form submission or script navigation; the gate cannot see that request's URL before it is sent (part 2 egress gate).

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. Finishes under 150k.
