# OSS-10w-r: Switching back after a project root-key rotation

Board section: LATER promoted at the coordinator's request (2026-10-09), a D-048 exception Mark confirmed (2026-10-09).

**Requirements:** OSS-10 (installations may follow any fork, and come back), UPD-8 (TUF: "keys rotate and revoke without reinstalling"; reuse a maintained implementation), OSS-9 (a fork's root is never the project's authority).

**Needs:** OSS-10w (merged #323), OSS-10w2 (page wiring, in review). Touches the files OSS-10w2 touches; merge origin/main before review.

**Risk tier:** A (trust root of the updater). Strongest model; security lens with an explicit threat check.

## Problem

WF1 admits a switch back (an empty follow name) only for a root whose root-role keys equal those of the root the image ships (`follow.rootKeys`/`sameKeys`). Once the project rotates its root keys (UPD-8), the project's current root no longer matches, so switching back fails closed and the owner's only route is a named follow of the project, which leaves the box recording a "fork" (LATER OSS-10w-r; U13 limit (b)).

## Spec basis for chain verification

SPEC UPD-8 makes update metadata TUF, with root keys that "rotate and revoke without reinstalling", through a maintained implementation. TUF's client workflow (spec §5.3.4–5.3.5) defines a rotation chain: root N+1 is trusted only when it is signed by a threshold of root N's root keys and a threshold of its own, and its version is exactly N+1. `Store.Check` already walks the chain this way with go-tuf's `trustedmetadata.UpdateRoot` and the box's threshold floor on every link (U3). So the SPEC already says how a chain is verified; this package applies the same walk to switching back. No L1 spec diff is needed.

## Design

1. **Anchor.** The walk starts from the newest project root this box trusted: when a named follow leaves the project chain (no `source.json`), `Store.FollowRoot` first saves the root being left as `project_root.json` (a narrowing write, before the switch marker). If no record exists, the anchor is the image's shipped root.
2. **Admission (WF1').** A held root is the project's when either
   - its root-role keys (by key material) equal the anchor's and its version is not below the anchor's; or
   - a walk from the anchor through the owner-brought links, each passing `UpdateRoot` (old threshold, new threshold, version exactly +1) and the threshold floor, ends at exactly the held root's bytes.
   Links come only from the owner (the page's root file input takes several files); the target is the newest version brought. Links at or below the anchor's version are history the box passed: skipped, never walked, so the owner may bring every project root file without knowing the anchor. A target with other keys must be newer than the anchor. Links beyond `update.MaxRootRotations` are refused.
3. `update.ProjectRoot(anchor, target, links, opts)` holds the rule; the executor calls it at describe time (`Project`, so the page offers switching back only when Execute admits it) and again at Execute.
4. Plumbing: `localapi.FollowRoot` gains `Chain [][]byte` (each at most `MaxRoot`, at most `MaxRootRotations`); `localsrv`, `daemon`, `agentosd` pass it through; `localui` reads every `root` part, sends the newest-version file as the root and the rest as the chain.

## Threat model

| Threat | Defence | Test |
|---|---|---|
| Forged chain link: a link signed by its own new keys but not by a threshold of the previous root's | `UpdateRoot` verifies the old root's threshold | forged-link test |
| Link under the old IDs with other key material (labels, not keys) | signatures verify against the anchor's key material | forged-link test (`forged`) |
| Chain rooted elsewhere: a fork that rotates its own keys, presenting its own v1→v2 | walk starts at the anchor, so the fork's v2 is not signed by project keys; the fork's root is followable only under a name | rooted-elsewhere test |
| Rollback: an older, validly chained project root (one whose keys a later rotation revoked), after the box had trusted a newer one | anchor is the newest project root the box trusted; a target not above it (other keys) is refused, and links at or below it are skipped, so no branch below it is walked | rollback test |
| Gap or replay in the chain (v1→v3, a duplicate v2) | `UpdateRoot` requires version exactly +1 | gap test |
| Weak intermediate root (threshold 1) vouching for the next | floor on every link, as `Check` | weak-link test |
| Expired target | `DescribeRoot` checks expiry at the clock guard's Latest (WF2), unchanged | existing |
| Resource exhaustion by many links | count bound and per-file `MaxRoot` | bound test |

**Residual (documented in U13):** a box that never trusted a project root newer than the shipped one cannot tell a stale but validly chained and unexpired project root from the current one (TUF's freeze limit; bounded by root expiry, as a fresh install from the same image is). An attacker holding a threshold of *rotated-out* project root keys can forge a branch from any anchor at or below the rotation, which TUF accepts by design for clients that have not seen the rotation.

## Acceptance tests (REQ: OSS-10, UPD-8, OSS-9)

1. After the project rotates root keys (v1→v2, new keys), switching back to v3 with no links is refused (v2 alone is its own one-link chain from v1, so it is admitted); with links [v2] and target v2, or [v2, v3] and target v3, it is admitted, every walked root's keys join `seen_keys`, `Project` agrees at describe time, and the store follows the project (no `source.json`).
2. Forged link: v2 signed only by its new keys, or by other material filed under the shipped key IDs: refused, nothing changes.
3. Rooted elsewhere: a fork's v1→v2 rotation is refused as the project's; it can still be followed under a name.
4. Rollback: the box trusted project v3 before leaving; a switch back to v2 (chained from v1) is refused; v3 itself and v4 chained from v3 are admitted.
5. Gap: links [v3] from anchor v1 refused.
6. Weak link: an intermediate root with root threshold 1 refused.
7. Bound: more than `MaxRootRotations` links refused before any verification.
8. `FollowRoot` leaving the project chain records `project_root.json`; leaving a fork for another fork does not overwrite it.
9. Page: `localui` sends several brought files as root plus chain; `localsrv` refuses a chain over the bounds.

## File scope

- `broker/update/follow.go`, `broker/update/projectroot_test.go`, `broker/update/ASSUMPTIONS.md` (U13)
- `broker/follow/follow.go`, `broker/follow/follow_test.go`, `broker/follow/rotation_test.go`
- `broker/localapi/localapi.go`
- `broker/localsrv/localsrv.go`, its follow tests and the `localsrv_test.go` rig
- `broker/daemon/daemon.go` and its follow tests
- `broker/localui/follow.go`, its template (`pages.go`) and follow tests
- `broker/cmd/agentosd/follow.go` and its follow tests
- `BOARD.md` (row), `LATER.md` (remove OSS-10w-r), this brief

## Usage estimate

~150k tokens in one builder session; checkpoint after the update and follow packages are green.
