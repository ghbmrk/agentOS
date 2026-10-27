# MAIL-reader-sock: the mail clerk's quarantined read over a frame

Work item #3421, filed from [briefs/MAIL-main.md](MAIL-main.md) (PR #3442). Tier A, release. Checked on main at 764887f with #3442's head 1308544. Two slices, one session each, in order. MAIL-reader-sock-a and MAIL-world-a both edit `cmd/agentos-clerk-mail/main.go` and `main_test.go`, so whichever starts second waits for the first's merge (D-111).

**Why.** `run.MailConfig.Ask` (`inbox.Ask`, PLN-2) has no production implementation. MAIL-main-a's `Ask` always fails (`errNoReader`), so every mail stays unclassified and the clerk acts on none. D-154 rule 4 keeps the reader out of every keeper process. The mail clerk therefore sends each mail's bounded text over a typed frame to a reader process on the main side. That process gets a model's reply through the model clerk (CLK-7, metered) and returns it. `inbox.Read` stays the one judge of the reply: only an exact class word counts, and anything else leaves the mail unclassified.

**Standing rules.** D-154: only typed frames cross, the caller's side comes from the listener, and each end checks the other's uid (SO_PEERCRED), as `kernel/proc/wire.go` does. D-158: the mail's text is private, so it goes only to a route nobody else can read or to a route a class key names for the reader's class, and the kernel, never the caller, sets the class. PLN-2 / D-141: the reader runs with no tools, keys or plan. The box has no local generative model on main (`broker/infer` serves embeddings only), so until one passes HLD-3 the route is the model clerk's.

**Acceptance tests:** per slice, under "Acceptance tests (a)" and "Acceptance tests (b)" below.

## Slices

| Slice | What | Needs | Files |
|---|---|---|---|
| **MAIL-reader-sock-a** | The frame (`clerk/readerwire`), the mail clerk's end (a cached ask over the frame) and the reader's serving end as a library, tested with a fake model | MAIL-main-a (#3442) | below |
| **MAIL-reader-sock-b** | `cmd/agentos-reader`, the main-side process, its binding to the model clerk under the reader's fixed class, and its unit | a; the model clerk's process (#2780 b2b, briefs/MIG-4-untrusted-exit-b.md) | below |

## MAIL-reader-sock-a

1. **The frame** (`broker/clerk/readerwire`, a new package). It links only the standard library and `sockets`, and never `clerk/inbox`: `clerk/inbox` links `kernel` and `imapsmtp`, so a main-side reader must not import it. Its own type is `type Ask func(ctx context.Context, prompt string) (string, error)`, which converts to `inbox.Ask` in the mail clerk's main. One connection per call, as in `kernel/proc/wire.go`. The call is one JSON line, `{"v":1,"op":"read","prompt":"<base64>"}`. The prompt is base64 (standard encoding), so its size on the wire is fixed at 4/3 of its bytes whatever they hold, and invalid UTF-8 from the 16 KiB cut survives intact. `readerwire.MaxPrompt` is 24 KiB of raw prompt, and the call is at most `4*ceil(MaxPrompt/3)+64` bytes on the wire. The answer is one JSON line, `{"reply":...}` or `{"err":"<closed word>"}`, at most 256 bytes on the wire, with the reply at most 64 bytes counted after decoding (a reply that escaping pushes past 256 bytes on the wire is refused, which fails closed). A longer reply is refused, never cut. The closed error words are `unavailable`, `refused` (no route admits the call) and `too-large`. Any other answer, version or op is refused.
2. **The mail clerk's end:** `readerwire.Dial(sock string, uid int, timeout time.Duration) Ask`. It dials, checks that the listener's uid is `uid` (refusing with nothing sent otherwise), applies one deadline to the whole call (default 60 s), writes, reads and decodes. Every failure returns an error, so the mail stays unclassified. **A down reader cannot hold a read.** `inbox.Read` asks once per mail, in turn, so 200 mails at 60 s each could hold one read for over three hours. After a failure of the reader itself (a dial error, a wrong uid, a deadline, `unavailable` or `refused`; not a malformed or over-long reply, which fails only that mail), the next calls fail at once, with nothing dialled, for 60 s. A read whose reader is down therefore costs at most one timeout.
3. **The cache.** Each read re-classes the newest `readMax` mails (`inbox.DailyCap`, 200, each up to 16 KiB), so an uncached `Ask` re-sends about 3 MB of mail to a metered route on every read. The main wraps `Ask` in a per-process cache keyed by the SHA-256 of the prompt. It holds at most 4,096 entries and evicts least recently used. Only successful replies are cached. Nothing is written to the drive, and a restart re-asks.
4. **The serving end:** `readerwire.Serve(ln net.Listener, model func(ctx, prompt string) (string, error))`, with `readerwire.Listen(path, mailUID)` built on `sockets.ListenPeers`. Each connection carries one call: a bounded read, a bounded decode and one model call under the connection's deadline. A reply over 64 bytes, or a model error, is answered with its closed error word, never with the model's text. At most 8 calls run at once (`proc.ServeConns`'s pattern), and the rest wait in the listen backlog.
5. **Wiring.** `cmd/agentos-clerk-mail` takes `-reader-sock <abs path> -reader-uid <uid>`. Without the flags, `Ask` stays the failing one. With them, it is the cached `readerwire.Dial`. The reader's uid must be positive and distinct from the other three peer uids, and `procguard.Isolate` gets it too. `inbox` exports `MaxPrompt` (the question's length plus `readBytes`), and the main's test checks that it is at most `readerwire.MaxPrompt`. Update the main's ASSUMPTIONS row MAIL-main-a-5 for the reader half.

**Requirement IDs:** PLN-2, D-154 rules 1, 2 and 4, D-158, CLK-7 (cost: the cache).

**Acceptance tests (a):**
- `clerk/readerwire/readerwire_test.go::TestReadRoundTrip`: a fake model's class word comes back as the reply, and `inbox.Read` over it classes the mail.
- `readerwire_test.go::TestFrameBounds`: a prompt over `MaxPrompt` is refused before dialling (`too-large`, nothing sent). A prompt of `MaxPrompt` bytes made of `<`, NUL, control and invalid UTF-8 bytes crosses intact and within the wire bound. A reply of 65 bytes, an answer over 256 bytes, trailing data, another version, an unknown op and an unknown error word are each refused. Fails if a long reply is cut and passed, or if escaping grows a call past its bound.
- `readerwire_test.go::TestEachEndChecksTheOthersUID`: a listener under another uid gets nothing written, and a caller under another uid is closed unread. The root-only half creates the sockets as two uids and is skipped otherwise; the CI step that runs `TestRealMailClerkAsRoot` also runs it and fails unless it ran (`tools/require_ran.py`).
- `readerwire_test.go::TestModelErrorsStayClosed`: a model error whose text is a class word, or holds the prompt, reaches the mail clerk only as `unavailable`.
- `readerwire_test.go::TestServeBoundsConcurrency`: 20 slow calls run at most 8 at once, and a hung model ends at the deadline.
- `readerwire_test.go::TestADownReaderFailsFast`: with no listener, or with a reader that hangs, 200 calls take at most one timeout plus 1 s in all, and dial at most once. Calls dial again after the 60 s pause (on a fake clock).
- `cmd/agentos-clerk-mail/main_test.go::TestReaderFlags`: a relative path, a uid that is 0, negative or equal to another peer's, and one flag without the other are refused.
- `main_test.go::TestTheReaderIsAskedOncePerMail`: two reads of the same mails over a counting fake reader make one call per distinct mail. A failed call is asked again at the next read.
- `main_test.go::TestTheMailProcessLinksNoMainSideCode` (existing) still passes, and `main_test.go::TestPromptFitsTheFrame` checks `inbox.MaxPrompt <= readerwire.MaxPrompt`.
- `readerwire_test.go::TestReaderwireLinksNoKeeperCode`: `go list -deps` of `readerwire` holds no `clerk/inbox`, `kernel`, `clerk/model`, `infer` or `localsrv`.

**Scope (a):** `broker/clerk/readerwire/` (new), `broker/clerk/inbox/reader.go` (export `MaxPrompt` only), `broker/cmd/agentos-clerk-mail/` (`main.go`, `main_test.go`, `ASSUMPTIONS.md`), `.github/workflows/ci.yml` (add the root test to MAIL-main-a's step), `tools/trusted_base_parsers.txt`.

**Guard files (a):** `tools/trusted_base_parsers.txt` gets `parser .../broker/clerk/readerwire -- the reader process's answers, in the mail clerk's process` (pre-approved). The builder runs `python3 tools/risk_tier.py` on the new package: if `core.txt`'s `clerk` lines do not class it A, it adds it to `TIER_A_BROKER` in `tools/risk_tier.py` (pre-approved). The `ci.yml` edit makes this a gate-file PR, so a separate Security accept is owed.

## MAIL-reader-sock-b

1. **`cmd/agentos-reader`** (main side, its own uid `agentos-reader`) takes `-sock <abs> -mail-uid <uid> -model-sock <abs> -model-uid <uid>`. It refuses root and any peer's uid, runs `procguard.Isolate`, and serves `readerwire.Serve` with a model function that makes one call to the model clerk. That call carries a `maxOut` of 8 tokens and no tools, system prompt or history. The process holds no credential, no state directory and no network (its unit: `PrivateNetwork=yes`, no writable path but its runtime directory).
2. **The class is fixed by the model clerk, not by the reader.** The model clerk serves the reader on a socket of its own that admits only the reader's uid. Every call on that socket has the fixed reader class (`inbox-read`), and the model clerk admits it only on a route the kernel's key check allows for that class (D-158): a route nobody else can read, or one a class key names. If no route admits a call, the reader answers `refused`. That socket and its class check are the model clerk's code (#2780 b2b's process), added in this slice. If, at slice b's start, the kernel has no per-class key check for the model clerk to call, the builder stops before writing code and posts on #3421 for the coordinator to take to Decisions: which key meters and admits the mail clerk's reads.
3. **The unit:** `agentos-reader.service` with a sysusers line, started after the model clerk, `Restart=always`. The mail clerk's unit gets `-reader-sock` and `-reader-uid` (MAIL-unit's file, by then on main). The image's binary list and `tests/test_image_keeper.py` gain checks that the unit has no network and the user has no shell.

**Requirement IDs:** PLN-2, D-158, CLK-7, D-154 rules 1, 2 and 4.

**Acceptance tests (b):**
- `cmd/agentos-reader/main_test.go::TestFlagsAndRefusals`: root, a peer's uid, relative paths and equal uids are refused before any socket opens.
- `main_test.go::TestReaderCallsCarryNoTools`: a fake model clerk socket records one call per read, with `maxOut` 8 and only the prompt.
- The model clerk's test, `TestReaderSocketFixesTheClass`: a call on the reader's socket is admitted only under the reader class's key. A caller under another uid is refused. A refused admission reaches the mail clerk as `refused`, and the mail stays unclassified.
- `main_test.go::TestTheReaderLinksNoKeeperSecrets`: `go list -deps` holds no `clerk/seal`, `tpmseal`, `clerk/inbox/imapsmtp` or `clerk/plan`.
- `tests/test_image_keeper.py`: the reader's unit has `PrivateNetwork=yes` and its own user, and the mail unit names the reader's socket.

**Scope (b):** `broker/cmd/agentos-reader/` (new), the model clerk's process files, named at b's start from #2780 b2b's merged PR (its reader socket and that socket's test only; b does not start before b2b merges), `image/` (the reader's unit and the sysusers line; the mail unit's two flags), `image/build.sh`, `tests/test_image_keeper.py`, `broker/core/core.txt` (a `wiring` line only if the reader counts as trusted; the builder records the reading in ASSUMPTIONS), `tools/g1_scope_g2.txt` (`allow broker/cmd/agentos-reader/`), `tools/risk_tier.py`.

**Guard files (b):** `tools/g1_scope_g2.txt`, `tools/risk_tier.py` (`cmd/agentos-reader` in `TIER_A_BROKER`: it handles the owner's mail text) and, if used, `broker/core/core.txt`, all pre-approved. This is a gate-file PR, so a Security accept is owed.

**Recurring kinds (reviews/security/README.md, keeper rows):** a reply passed on that the keeper did not bound (here a 64-byte cap, and `inbox.Read`'s closed list); a peer check by mode instead of uid; a model error's text crossing as data; a caller choosing its own class or route; a test that cannot fail as a plain user.

**Lifecycle (integration owner: MAIL-reader-sock-b).** First boot: the reader starts after the model clerk. Until both are up, `Ask` fails, the mails stay unclassified, and the next read asks again. Reader restart: the mail clerk's next call dials afresh, and the cache in the mail clerk survives. Mail clerk restart: the cache is empty, so the first read re-asks every mail once. Update: no state. Model clerk route refused or paused: `refused`, the mails stay unclassified, and STATUS's existing plan line names the route. The test matrix covers start, reader restart and a refused route in slice b; slice a tests its own stage.

**Usage estimate:** a: about 90k tokens. b: about 110k tokens.
