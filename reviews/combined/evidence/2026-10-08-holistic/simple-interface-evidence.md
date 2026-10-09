# Simple text/call review: evidence scope

Reviewed source: `a52a678a4f4d854eaf737ffaa8c3777781efea56`, 2026-10-08. Local merge head before advisory edits: `9a6c8bbb459b7dba9751e2c3c8e4110651876e26`; runtime and SPEC matched the pinned source. Earlier files in this directory retain their own source; these are additional checks, not a relabelling of earlier evidence.

## Source review

Three bounded read-only reviews examined owner conversation versus authority; defaults, setup and resource choices; and voice, task continuity and artifact delivery. The coordinator synthesized their evidence into the [report](../../2026-10-08-simple-interface-review.md) and ARCH1-4 acceptance. Existing UX3/UX4 draft scopes were consulted for ownership only; their runtime changes are not assumed merged. Fresh independent L3 and a separate security/potency/UX challenge are recorded in PR #447 against the final reviewed tree.

## Existing component tests

Native macOS arm64, bundled Go 1.26.8, synthetic fixtures only. Commands below run from `broker/`; replace `go` with the local Go 1.26.8 executable and use a writable external cache. Results transcribed from the author reviewers' tool output; raw logs were not retained in this evidence directory.

```sh
GOCACHE=/private/tmp/simple-control-gocache GOTOOLCHAIN=local go test ./owner ./control ./question
```

`owner` passed (1.044s); `question` passed (0.910s). `control` could not compile on Darwin: its test dependencies reached `vm/overlay/delete.go`, where Linux `syscall.Unlinkat`/`Openat` and `Stat_t.Dev` type assumptions are unavailable/incompatible. Overall command exited 1; no control-suite pass is claimed.

Seven focused tests were also run with `-mod=vendor -count=1`:

```sh
GOCACHE=/private/tmp/agentos-simple-voice-gocache GOTOOLCHAIN=local go test -mod=vendor ./modem/at -run 'Test(GateDecodesEveryKeyAndLeavesNoToneForSpeech|GatePassesSpeechWithoutKeysUntouched|IncomingCallDecodesKeysInTheBrokerAndMutesThemForSpeech)$' -count=1
GOCACHE=/private/tmp/agentos-simple-voice-gocache GOTOOLCHAIN=local go test -mod=vendor ./owner -run 'Test(TextsReachTheBrokerFromTheModemAndControlWordsWorkWithModelsDown|StopIsNotQueuedBehindAHungVerifier|SlowAgentNeverDelaysStop|RestartHandsOpenRequestsToReissue)$' -count=1
```

Both passed (`modem/at` 0.992s; `owner` 0.433s). These cover synthetic speech/key separation, model-independent text/STOP primitives and restart hand-off. They do not test an assembled owner call service, keypad usability, real audio leakage or cross-channel task continuity.

## Required repository checks

- `python3 tools/doclint.py` and `git diff --check`: pass.
- `python3 tools/trace.py --check`: the inherited generated file was stale. Regeneration followed by check passed; TRACE.md was restored and is not part of this change.
- `python3 -m unittest discover -s tests`: first sandbox run encountered six loopback-listener errors, plus six canary failures. Rerun with synthetic loopback permitted and bundled Go on PATH ran **214 tests, six failures, 33 skips, no errors**. All failures are in native Linux canary/sweeper assumptions: decoded-only leak, memory leak, report secrecy control, shipped registry, environment/files sweep and memory-only sweep. Darwin has no Linux `/proc` surface; product target builds also use Linux-only APIs. This local suite is not green. Linux PR CI status is recorded separately in the PR.
- No runtime files were edited, so there is no new Go requirement coverage or runtime regression-test claim.

## Qualification boundary

No real credentials, accounts, model provider, owner call, carrier/modem hardware, physical actuator, raw worker, full cross-silo workflow or owner-comprehension study was exercised. No measured attention saving, latency, security guarantee or productivity gain follows from these component checks. Proposed interaction examples in the report are acceptance targets. The draft registers work and evidence obligations; it does not close them.
