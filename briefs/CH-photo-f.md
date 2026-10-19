# CH-photo-f: a denied photo delete can be retried

Board section: Human-native texting (photos). Work item: #2320. Follow-up of CH-photo (#2307); Security review point 3, comment 6241468539. **Tier A or B**: run `tools/risk_tier.py` on the diff and hand off if A.

**Why.** CH-26: the owner's delete is never refused, and expiry deletes on time. Failure path: a transient policy denial at Authorize ends `photo:delete:P<n>` as Denied. The delete ID is fixed per photo and `run` (`broker/photo/keep/store.go:346-370`) resumes an existing ID, so every later `Delete` (:426) and `Sweep` (:508) reuses the Denied intent and returns `ErrNotDone`; the photo stays kept forever.

**Requirements:**
- CH26-R1: a delete whose latest attempt was Denied is retried by the next owner `Delete` and the next `Sweep`, and succeeds when authorization now passes.
- CH26-R2: attempts are separate intents, `photo:delete:P<n>:<k>` (or Denied is retryable for delete); the view folds all attempts of a photo into one.
- CH26-R3: `Erase` and `DeleteAll` (:433) cover every attempt's intent, so no attempt leaves a record behind.
- CH26-R4: an attempt that is in progress or done is resumed, not duplicated (existing behaviour kept).

**Acceptance tests:** in `broker/photo/keep/store_test.go` (REQ: CH26-R1..R4)
- `TestDeniedDeleteIsRetriedByOwnerDelete` and `TestDeniedDeleteIsRetriedBySweep` (R1; mutant: reuse the Denied intent).
- `TestViewFoldsDeleteAttempts` (R2).
- `TestEraseCoversEveryDeleteAttempt` (R3; mutant: erase only `<k>`=0).
- `TestInProgressDeleteIsResumedNotDuplicated` (R4).

**Out of scope.** Changing the authorization policy; the sweep order.

**Scope:** `broker/photo/keep/store.go`, `store_test.go`, `broker/photo/ASSUMPTIONS.md` if a row changes, this brief.

**Usage estimate:** 60k tokens; checkpoint at 45k.
