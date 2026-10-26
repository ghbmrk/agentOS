# MIG-4-recovery-f: backups carry the page CA key and the edge keys (BAK-1, CH-9, HW-15), split into f1 and f2

Work item: #3253, found briefing #3191 (`briefs/MIG-4-recovery-e.md`, "Unowned gaps"). Tier A. Folds in #3168 (OWN-ca-backup) and retires #3166 (OWN-page-ca-seal).

**Decided (Mark, 2026-10-26, Decisions card cmsg_01R91wiieBzMSvPKFsAJVvuKCSPvYYMZpQY6nGnEFboyQw, "A, in the kernel"):** the kernel holds the page CA key from the sealed store. The other options were agentosd keeping it and handing the kernel a section sealed to the recipient, or a new clerk.

## The gap

BAK-1 says a backup carries the page CA key (CH-9) and the edge key with the record of revoked edge keys (HW-15). The kernel process takes backups (e2 #3250, e3 #3251), but it holds none of these, so e3 writes the `Manifest`'s `PageCA`, `EdgeKey` and `RevokedEdge` empty. An ordinary restore (#3186) would then find no page CA, the printed fingerprint would change, and the owner could not tell a restore from an attacker's box.

## Decisions

1. **The page CA lives in the sealed store and the kernel holds it (Mark's card).** Today agentosd generates the authority and seals it in its own state directory (`broker/pageca`, `broker/localsrv/certify.go`, #3153), and #3166 would hand agentosd an STO-2 sealer for it. agentosd is outside the trusted base (KRN-2), CLK-1 counts private keys as reusable authentication material, and a copied CA key can impersonate the page, where passkeys and codes are entered, until a compromised restore replaces it (REC-5, §19 risk 30). So the key moves to where the recovery key's recipient goes (e1): enrollment generates it (`pageca.New`) and puts it in the sealed store under a new `handoff.PageCAEntry` (`kernel/page-ca`). The unlock step hands it to the kernel on descriptor 3 in `KernelKeys`. Nothing has wired the authority on a shipped box yet (#3166 is queued, and no production sealer exists before STO-2), so there is no box to migrate.
2. **The kernel signs the page's serving certificate.** A new owner-socket call, `certify`, takes the page's P-256 public key (PKIX DER, at most 128 bytes) and returns the leaf and the authority's certificate, using `pageca.Authority.Issue` unchanged. The leaf names only the page name, which the authority's name constraint already enforces. The call keeps today's fixed refusals: `no authority` on a store with no entry, and `restore` on a claimed box with none. agentosd's `localsrv` keeps `OpCertify` for the page and forwards it to the kernel, so `localui` and its tests do not change. A rooted owner side can still get leaves while it is rooted (it holds the serving key anyway), but it can no longer copy the 30-year key.
3. **The kernel writes the CA into every backup.** e3's `backup.Write` call fills `In.PageCA` with the sealed-store form (certificate and PKCS#8 key). The kept `Record` gains the CA's fingerprint, which is public, so restore (#3186) refuses a backup whose CA does not match the fingerprint recorded with it, and the owner checks that against the Owner Card (CH-9).
4. **Edge keys are log state, so the log section already carries them (KRN-1).** SPEC keeps all kernel state in the log. An edge enrolment is a widening and a revocation is a narrowing (HW-15), so when the core side of the edge link is built, both are kernel log kinds. A backup's `log` section then holds the enrolled key and every revocation, and a restore trusts none of them until the owner's page step anyway (REC-2, HW-15). The `Manifest`'s `EdgeKey` and `RevokedEdge` fields would be a second copy that could disagree with the log, so f1 removes them. The core's own private link key is not backed up: a restored core re-pairs the edge in REC-2's one visit and makes a new one.
5. **Nothing holds an edge key today.** No BOARD or PLAN row builds the core side of the edge link (HW-15). That gap is outside this row; it is raised on #3253 for the coordinator to file. Decision 4 is the constraint that row inherits.

## f1: the kernel holds the page CA and puts it in backups (#3253)

**Scope:** `broker/clerk/handoff/handoff.go` (+test: `PageCAEntry`, a size-bounded `PageCA []byte` in `KernelKeys`), `broker/cmd/agentos-enroll/main.go` (+test: generate and store the authority), `broker/cmd/agentos-unlock/main.go` (+test: hand it), `broker/kernel/proc/kernelmain.go` and `kernel/proc/backup.go` (+tests: hold it, fill `PageCA`, record the fingerprint), the `certify` line in `kernel/proc/kernelsock.go`, `broker/owner/kernelsock` (client method), `broker/backup/backup.go` (+test: drop `EdgeKey` and `RevokedEdge`, bump the manifest version, add the fingerprint to `Record`), `broker/pageca` (a `Marshal` and `Unmarshal` of the sealed form, so `Store` and the sealed-store entry share one encoding), their ASSUMPTIONS rows, this brief.
**Requirement IDs:** CH-9, BAK-1, HW-15 (the edge fields' removal, decision 4).
**Acceptance tests:**
- `cmd/agentos-enroll/main_test.go::TestEnrollStoresThePageAuthority`: the store holds an authority for the page name whose certificate opens with its key. Catches a box with no fingerprint to print.
- `clerk/handoff/handoff_test.go::TestKernelKeysCarryThePageCA`: round trip; an oversized or malformed value refuses.
- `cmd/agentos-unlock/main_test.go::TestUnlockHandsThePageCA`, and a store without the entry hands none.
- `kernel/proc/kernelsock_test.go::TestCertifyIssuesForThePageNameOnly`: a P-256 key gets a leaf for the page name that verifies against the authority; another curve, an oversized key or garbage refuses; a kernel with no authority answers `no authority`, and a claimed one answers `restore`.
- `kernel/proc/backup_test.go::TestBackupCarriesThePageCA`: a backup opened with `rk` holds the same authority, and its `Record` carries the authority's fingerprint.
- `backup/backup_test.go::TestManifestHasNoEdgeFields`: the new version has neither field, and the old version still opens.
**Needs:** e1 (#3191) and e3 (#3251), which edit the same files (D-111). **Guard files:** `broker/daemon/arc2_test.go` if `kernel/proc` newly imports `pageca` (its import rule allows stdlib crypto only, which holds). **Gate:** trusted-core files; a D-159 row cites CH-9 and BAK-1 as the approved design, if `trusted-base` grows.
**Estimate:** 90k tokens.

## f2: agentosd stops holding the page CA (#3289)

**Scope:** `broker/localsrv/certify.go` (+test: `OpCertify` forwards to the kernel's `certify`; `PageConfig` loses `Dir` and `Sealer`), `broker/localsrv/ASSUMPTIONS.md`, the `broker/cmd/agentosd` call site (serial chain, D-111), `broker/pageca/store.go` (delete `Store` and `OpenOrCreate` if nothing else uses them). The status page's restore line keeps its text: after f1 a restore does bring the authority back, which answers #3168's release finding (issuecomment-6400732768).
**Requirement IDs:** CH-9.
**Acceptance tests:**
- `localsrv/certify_test.go::TestCertifyForwardsToTheKernel`: the leaf comes from the kernel; the kernel's `no authority` and `restore` reach the page as today's codes.
- `localsrv/certify_test.go::TestAgentosdHoldsNoAuthority`: agentosd's state directory never gains `page-authority.sealed`.
**Needs:** f1. **Estimate:** 50k tokens.

## Rows this changes

- #3168 (OWN-ca-backup) is done by f1 and restore (#3186): close it as superseded when f1 merges.
- #3166 (OWN-page-ca-seal) is no longer needed: agentosd gets no sealer for the CA. Close it as not planned.
- OWN-card-ca (the Owner Card fingerprint) reads the fingerprint from the kernel, not from agentosd.

## Residual risks

1. Whoever reads a decrypted backup holds the page CA (§19 risk 30), which is unchanged. Only a compromised restore replaces it.
2. A rooted owner side can obtain serving leaves for the page name while it is rooted. Each lasts at most 825 days and cannot be revoked; a shorter leaf would narrow this, and is a later choice.
