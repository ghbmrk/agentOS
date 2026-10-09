# Security review 2: code merged before the lens gate, and CI on a public repo (main @ 76ac0b9)

**Scope.**
- Everything on `main` since run 1 (e841b78): PRs #8 to #142, 890 commits.
- Not re-reviewed: anything the per-PR security lens gate already signed off. That covers every feature PR merged after the gate started (2026-10-04 22:03 Eastern) and every spec change since spec v0.12 (#15, which went through the consolidated lens fix-list).
- Reviewed: the code PRs merged before the gate existed, which had only an L3 review: #17–#19, #21–#27, #29, #30, #32–#38, #40, #44, #48.
- Also reviewed: the CI workflows, which skip the gate as tooling, now that the repository is public (since 2026-10-05 03:11Z).

**Method.** The run 1 threat model (assets; adversaries G, T, S, D, C, W, U) applied to the **current** code on those paths, with an explicit threat check on the security-critical ones (broker, vault, executors, recovery, VMs). Findings were verified by reading the code. Findings 1 and 2 were also confirmed by running a probe test that was then thrown away.

**Labels:** [Fact] verifiable · [Inference] reasoned, untested.

**Costs:** each proposal states its cost to UX and to potency. "None" means none found, not none possible.

---

## Summary

| # | Finding | Severity | Adversary | Proposal | UX cost | Potency cost |
|---|---|---|---|---|---|---|
| 1 | Agent-written recipient text is printed inside the broker's approval text | **Medium** | G | Only canonical identifiers are shown; anything else goes to the Wi-Fi page → code (CH-10 already requires it) | Low | None |
| 2 | A chain of symlinks in a restore escapes the restore root | **Medium** (latent) | D | Refuse `..` links outside the layers and links that pass through a restored link → code | None | None |
| 3 | A guest can fill the disk the journal and owner state live on | **Medium** | G | Hard per-machine disk quota; the broker's reserve is enforced by the file system → spec RES-4 and code | None | Low |
| 4 | Machine cgroups limit only memory | **Medium–Low** | G | CPU, I/O and process limits; machines weigh less than the broker → spec RES-2 and code | None | Low |
| 5 | Second-line sends accept short and premium-rate numbers and have no cap | Low now, Medium once wired | G | Full E.164 only unless the owner made the contact; one shared cap per line → spec ADP-12 and code | Low | Low |
| 6 | The screenshot check in the S5 executor ignores pixels | Medium for CRED-4b | G | CRED-4b withholds screenshots of account-security pages and QR codes; add A14 canaries → later (CRED-4b brief) | Low | Low |
| 7 | Hostile senders can push the owner's long texts out of the shared reassembly buffer | Low | any sender | Per-sender cap and reserved owner slots → code | None | None |
| 8 | Anyone on GitHub can skew METRICS.md | Low | U | Count only collaborator reviews and same-repo runs → code | None | None |
| 9 | ci.yml pins actions by tag and keeps the checkout token | Low | U | Pin by SHA, `persist-credentials: false` → code | None | None |

Nothing found lets G gain authority or read credentials. Findings 1, 3 and 4 are the ones to fix first.

---

## Findings

### 1. Agent-written recipient text is printed inside the broker's approval text (CH-10, CH-12, A6) — Medium

[Fact]
- `broker/guest/mcp.go:241-247` checks recipients only for count and length.
- For an unverified item, `broker/grants/gate.go:689-691` passes the guest's raw `strings.Join(in.Recipients, ", ")` to the renderer.
- `broker/owner/render.go` (`recipientText`) prints up to 100 characters from a set that includes space and `. , : ( ) ! ?`. It skips the `longDigits` masking every other field gets.

A recipient of `boss@corp.com. Expires 23:59. Reply YES K7 482913 or NO K7. 2 archive old` is rendered inside the broker's own approval text, sent from the box's number.

**Attack path.**
- G plants a fake expiry, request ID, item list or code inside a real approval request.
- The owner may approve something other than what they read.
- If the owner sends the planted code, it counts as a wrong code. Five lock the low tier and ten switch on challenge mode (CH-18), which gives G a cheap denial of service against the owner.

**Limits.** G cannot approve its own request. Unverified items are always high tier, and the `UNVERIFIED` prefix stays.

**Proposal.**
- `recipientText` shows a recipient only if it is a canonical identifier with no spaces: an email address, an E.164 number, or `acct …1234`.
- Anything else falls back to the existing "N recipients, see the Wi-Fi page" wording, which already makes the item approvable only on the local page.
- Apply `longDigits` to recipients.

CH-10 already requires this ("rendered by the broker in fixed wording from verified fields … canonical identifiers"), so no spec change is needed.

**UX:** low; unusual recipients move to the Wi-Fi page. **Potency:** none.

### 2. A chain of symlinks in a restore escapes the restore root (REC-1, recovery R3, V17) — Medium, latent

[Fact] Outside the machine layers, `broker/recovery/bundle.go:693` accepts a symlink if `staysIn` (`:744-750`) passes. `staysIn` checks the link text lexically and ignores links already restored. So this chain passes one link at a time:

```
a -> .
b -> a/..
c -> b/..
d -> c/..
e -> d/target
```

On disk, the chain resolves outside the restore root. A probe test showed `broker/e` resolving to `<dst>/../../target-outside` through both `Restore` and `RestoreDrive`.

**Attack path.**
- D writes the chain onto the old drive offline, and the owner later runs `RestoreDrive` from it.
- The backup MAC does not help, because the box signs whatever its tree holds.
- [Inference] The broker runs as root, so once restore is wired up, any later open through a planted link (for example a state directory replaced by a link) writes to host files.
- Today only `cmd/agentos-a8scan` imports `recovery`.

**Proposal.**
- Outside the layers, refuse a symlink that is absolute or has any `..` element.
- Also refuse one whose joined target passes through a link already restored (keep a set of restored links and check every prefix).
- Add the chain above as a regression test.

**UX:** none. **Potency:** none. [Inference] The box's own state outside the layers uses no `..` links.

### 3. A guest can fill the disk the journal and owner state live on (RES-4, REV-1) — Medium

[Fact]
- **Shared disk.** Machine upper layers live in `/var/lib/agentos/machines` (`broker/cmd/agentosd/main.go:224`), on the same file system as the journal, owner state, meter, guest inbox, recall index and learning state (`main.go:211, 228-239`).
- **No limit on live writes.** `vm/ASSUMPTIONS.md` V19 says "The guest is not stopped from writing". `MaxLayerBytes` is optional (`broker/vm/vm.go:185-187`), and agentosd never sets it.
- **Console log.** It goes to a host file through runsc's stdout (`broker/vm/gvisor/gvisor.go:111-121`) and is rotated only at start (V23).
- **Reserve.** The RES-4 reserve is checked only before snapshots and copies (`vm.go:849-866`).
- **Snapshots.** They can run every 2 s, triggered by each `effect_request` (`broker/guest/plane.go:170`). Snapshots younger than 10 minutes are never pruned (`broker/vm/prune.go:33`).

**Attack path.**
1. G writes a large file and sends effect requests, so snapshots of that layer use up space down to the reserve. Other machines' snapshots are then refused, and they lose REV-1 rollback points.
2. G's live writes then take the reserve itself.
3. Journal, owner-state and meter writes hit ENOSPC. The meter ignores save errors (`broker/meter/meter.go:479`).
4. Effects fail closed because intents cannot be journaled. That is safe, but the box stops working.

[Inference] Not every component's ENOSPC path was traced, for example whether CH-18 attempt counters still persist.

**Proposal.**
- **→ spec RES-4:** the reserve is enforced by the file system (a quota or a separate volume), not only checked before snapshots, so no machine's writes can consume it.
- **→ code:**
  - a per-machine project quota or size-capped file system on each upper layer, from a declared disk budget;
  - `MaxLayerBytes` set by default;
  - the console piped through the broker with a cap;
  - meter save errors surfaced.

**UX:** none. **Potency:** low; a guest gets ENOSPC at its declared budget, which it can act on.

### 4. Machine cgroups limit only memory (RES-1, RES-2) — Medium–Low

[Fact]
- `broker/cgroup/cgroup.go:52-53` enables only `+memory`, and `:76-83` writes only `memory.*`.
- Nothing writes `cpu.weight`, `io.weight` or `pids.max`.
- The broker's group and the machines' group are siblings (`broker/cmd/agentosd/main.go:580-597`).

**Attack path.**
- G's busy threads or heavy I/O compete with agentosd on equal terms. That slows calls, STOP and STATUS, and journal fsync, which RES-1 says come first.
- [Inference] Under systrap each guest address space has a host stub process. Without `pids.max`, a fork bomb is bounded only by `memory.max`. This was not measured.

**Proposal.**
- **→ spec RES-2:** CPU, I/O and process-count limits per component; agent machines weigh less than the broker and foreground, and experiments weigh least.
- **→ code:** enable the `cpu`, `io` and `pids` controllers and set weights and `pids.max`.

**UX:** none. **Potency:** low; a machine slows only while foreground work is busy.

### 5. Second-line sends accept short and premium-rate numbers and have no cap (ADP-12) — Low now, Medium once wired

[Fact]
- `broker/modem/secondline/secondline.go:280-303` refuses only the owner's numbers.
- `dialable` (`broker/modem/at/driver.go:711`) and `encodeAddr` accept 1 to 20 digits, so premium short codes pass.
- Nothing outside the package calls `secondline.New` yet.

**Attack path.** Once the tool is wired, G texts or calls premium-rate numbers, which costs the owner money and has no limit.

**Proposal.**
- **→ spec ADP-12:**
  - recipients are full international numbers; a short code needs an owner-created contact;
  - the line's rate limits are one budget shared by every transport that line uses.
- **→ code:** this matches the security conditions already given for the HTTP-SMS line (C1 and the shared cap of 30 per hour, 200 per day, 10 per hour per recipient).

**UX:** low; the owner adds a short code as a contact once. **Potency:** low.

### 6. The screenshot check in the S5 executor ignores pixels (CRED-10, A14) — Medium for CRED-4b

[Fact] `spikes/S5-browser-actions/executor.py:205-219` withholds a screenshot only when redaction matched text in the accessibility snapshot. That snapshot does not include content drawn as an image, canvas or `aria-hidden` text. The clearest case is an authenticator-setup QR code, which carries the seed.

**Attack path.** The screenshot goes to the agent's workspace, and G reads it with OCR. Nothing in production imports the spike, but CRED-4b will inherit the design.

**Proposal (→ later, CRED-4b brief).**
- Withhold screenshots on pages the adapter marks as security or account settings, and on pages showing a QR code.
- Add A14 canaries: a token in an `aria-hidden` span, and a QR-encoded seed.

**UX:** low; some screenshots read "withheld". **Potency:** low.

### 7. Hostile senders can push the owner's long texts out of the shared reassembly buffer (CH-1) — Low

[Fact] `broker/modem/at/driver.go:86-88` sets `maxConcat = 32`, one limit shared by all senders. When it is full, the oldest partial text is dropped silently (`:466-469`, `:498-503`).

**Attack path.** A sender who keeps 32 fake first parts pending evicts the owner's multi-part text before its last part arrives. [Inference] This needs a sustained flood timed between the owner's parts.

**Proposal.** A cap of 4 pending texts per sender, plus slots that only the owner's number can use.

**UX:** none. **Potency:** none.

### 8. Anyone on GitHub can skew METRICS.md (L4 meta loop) — Low, integrity only

[Fact]
- `tools/metrics.py:56-58` counts any review whose body contains "L3", and `:190-192` never checks the reviewer.
- `:199-207` counts runs from fork PRs toward the flake rate.

**Attack path.** Since the repository went public, any account can post an "L3 accept" comment review or stage flaky fork runs. No text gets into the output: only verdict words and integers are written.

**Proposal.** Count only reviews whose `author_association` is OWNER, MEMBER or COLLABORATOR, and only runs whose head repository is this repository.

**UX:** none. **Potency:** none.

### 9. ci.yml pins actions by tag and keeps the checkout token (U) — Low

[Fact]
- `.github/workflows/ci.yml:17, 51, 78` use `actions/checkout@v4`, and `:20` uses `actions/setup-python@v5`. Every other workflow pins full SHAs.
- Checkouts in jobs that run PR code keep `persist-credentials` at its default (true).
- The token is `contents: read`, so the impact is small.

**Proposal.** Pin by SHA, as the other workflows do, and set `persist-credentials: false`.

**UX:** none.

---

## What was checked and held

- **Approval codes (CH-10, CH-18):**
  - constant-time compares, 6 random digits bound to one request, 15-minute expiry;
  - 3/5/10 limits, challenge mode capped at 48 a day, request IDs retired for 24 h;
  - code-generator codes and grid cells single use;
  - `sameItem` re-check and `spend` before dispatch.
- **Number alone vs a code (T, S):**
  - a texted code never unlocks a session, and a held message runs only on RUN;
  - control words are exact-match and only from the owner's number; alphanumeric senders are dropped.
- **Grants and change pipeline (ARC-2):**
  - guest origins are refused broker and `meta.*` actions; derived intent IDs come only from the gate; parse errors deny;
  - change classes come from path namespaces, and unknown ones fail;
  - only the owner's NO counts as a decline;
  - no path found for G to create, widen or replay a grant.
- **Vault:**
  - Argon2id with a floor and ceiling bound into AAD; AES-256-GCM;
  - secrets wiped; files 0600, written atomically with fsync;
  - fails closed on unreadable state; the drive holds no code verifier;
  - unlock and tier-4 attempts are counted durably;
  - backups sealed to the recovery key with chunked AEAD and a final marker.
- **Sockets:** one uid per socket through SO_PEERCRED, distinct uids enforced at start, directories 0700 or 0711.
- **Journal:** append-only, fsync, CRC and sequence number per record, single writer. There is no hash chain, which the spec does not require.
- **Local UI (W):**
  - access-point subnet only, exact host check (no DNS rebinding);
  - CSRF refused, SameSite=Strict cookies;
  - CSP, `no-store`, `X-Frame-Options: DENY`;
  - sign-in by code-generator code, 24 tries a day.
- **VM isolation (ARC-5):**
  - runsc with `--network=none` and minimal read-only, nosuid, nodev, noexec mounts;
  - host sockets reachable only through the services socket;
  - layer copies refuse device nodes and symlinks;
  - identity, label and lineage are derived by the broker.
  - Open: V18 (state directory mounted nosuid,nodev) belongs to the image build.
- **Recall and event bus (CAP-3, REV-5):**
  - owner and preference kinds are refused on the bus;
  - preferences need a single-use authenticated owner message;
  - labels come from an allow-list, and a search that is not public-only raises the machine to private;
  - results are wrapped as untrusted content.
- **Hint schema (OSS-1):** enumerated values only, a strict parser and a daily batch. It is not wired yet.
- **Modem:**
  - the PDU parser is bounds-checked; UCS-2 and GSM-7 are handled;
  - parts that conflict drop the whole text; owner matching is exact;
  - outbound is digits and hex only; udev sets 0600 for the modem uid.
- **Model egress (ADP-10):**
  - one declared inference path per provider, with path cleanliness checks;
  - server tools, remote sources and organisation headers are stripped;
  - no redirects, TLS verification on, response caps;
  - the router holds no key. This closes run 1 finding 15 on the proxy side.
- **CI (U):**
  - no `pull_request_target`, `workflow_run` or `issue_comment` triggers;
  - every workflow caps the token at `contents: read`;
  - the two write jobs (trace, metrics) run only on main and run no repository code;
  - no `${{ github.event.* }}` in `run:`; no caches;
  - downloads are checksummed (gVisor, Node, npm `--ignore-scripts`, mkosi by SHA);
  - GitHub-hosted runners only;
  - fixtures contain only synthetic canaries.
  - [Inference] Repository settings (fork-PR approval, branch protection, secret scanning) are not visible from the code.

## Decisions

Each spec change below is auto-decided: no lens gets meaningfully worse (CLAUDE.md, DECISIONS.md auto-decide rule).

- **RES-2:** add CPU, I/O and process limits. Security improves; UX is unchanged; potency is low cost, with machines slowed only under foreground load.
- **RES-4:** the file system enforces the reserve. Security and availability improve; UX is unchanged; potency is low cost, since a guest gets a disk budget it can act on.
- **ADP-12:** full numbers only unless the owner made the contact, and one shared cap per line. Security improves (G can't run up premium-rate charges); the UX cost is one contact entry for a short code; potency is low cost.

Code fixes (findings 1–5 and 7–9) need BOARD rows. They go to the coordinator to route. Finding 6 goes into the CRED-4b brief.

Nothing here needs Mark.

## Next run

- Confirm the code fixes for findings 1–4 landed.
- Check that V18 is set in the image (#41 follow-up).
- Re-check the ENOSPC behaviour of the CH-18 counters once the quota exists.

## Carried to run 3

- CH-20 [Risk] wording: under rule (a) the text summary is the reply's first sentence, so during an unlocked window S reads one sentence of private content per reply. "Summaries, not content" overstates it. Add a [Risk] line in run 3's spec diff (CH-20 design ruling, 2026-10-05).
